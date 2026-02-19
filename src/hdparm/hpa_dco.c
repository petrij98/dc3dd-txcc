/* hpa_dco.c
 * Modified by Andrew Medico
 * DC3/DCCI
 * 19 September 2008
 *
 * Dervied from hdparm.c by Mark Lord
 */

/* hdparm.c - Command line interface to get/set hard disk parameters */
/*          - by Mark Lord (C) 1994-2008 -- freely distributable */
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <endian.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <linux/types.h>
#include <linux/major.h>
#include <asm/byteorder.h>

#include "hdparm.h"
#include "sgio.h"
#include "hpa_dco.h"

const int timeout_12secs = 12;

__u64 get_lba_capacity (__u16 *idw)
{
	__u64 nsects = (idw[58] << 16) | idw[57];

	if (idw[49] & 0x200) {
		nsects = (idw[61] << 16) | idw[60];
		if ((idw[83] & 0xc000) == 0x4000 && (idw[86] & 0x0400)) {
			nsects = (idw[103] << 16) | idw[102];
			nsects = (nsects << 32) | ((idw[101] << 16) | idw[100]);
		}
	}
	return nsects;
}

static __u8 last_identify_op = 0;

void *get_identify_data (int fd, void *prev)
{
	static __u8 args[4+512];
	__u16 *id = (void *)(args + 4);
	int i;

	if (prev != (void *)-1)
		return prev;
	memset(args, 0, sizeof(args));
	last_identify_op = ATA_OP_IDENTIFY;
	args[0] = last_identify_op;
	args[3] = 1;
	if (do_drive_cmd(fd, args)) {
		last_identify_op = ATA_OP_PIDENTIFY;
		args[0] = last_identify_op;
		args[1] = 0;
		args[2] = 0;
		args[3] = 1;
		if (do_drive_cmd(fd, args)) {
			//perror(" HDIO_DRIVE_CMD(identify) failed");
			return NULL;
		}
	}
	/* byte-swap the little-endian IDENTIFY data to match byte-order on host CPU */
	for (i = 0; i < 0x100; ++i)
		__le16_to_cpus(&id[i]);
	return id;
}

void *get_dci_data (int fd, void *prev)
{
	static __u8 args[4+512];
	__u16* dci = (void*)(args+4);

	if (prev != (void*)-1)
		return prev;

	memset(args, 0, sizeof(args));
	args[0] = ATA_OP_DEVICE_CONFIG_IDENTIFY;
	args[2] = 0xC2;
	args[3] = 1;

	if (do_drive_cmd(fd, args)) {
		//perror(" ATA_OP_DEVICE_CONFIG_IDENTIFY failed");
		return NULL;
	} 

	return dci;
}

__u64 get_dci_maximum_lba (__u16* dci)
{
	__u64 sectors_before_dco = (__u64)dci[6]<<48 | (__u64)dci[5]<<32 | (__u64)dci[4]<<16 | (__u64)dci[3];
	sectors_before_dco += 1;
	return sectors_before_dco;
}

__u64 do_get_native_max_sectors (int fd, __u16 *id)
{
	int err = 0;
	__u64 max = 0;
	struct hdio_taskfile r;

	memset(&r, 0, sizeof(r));
	r.cmd_req = TASKFILE_CMD_REQ_NODATA;
	r.dphase  = TASKFILE_DPHASE_NONE;
	r.oflags.b.dev      = 1;
	r.oflags.b.command  = 1;
	r.iflags.b.command  = 1;
	r.iflags.b.lbal     = 1;
	r.iflags.b.lbam     = 1;
	r.iflags.b.lbah     = 1;
	r.lob.dev = 0x40;

	if (((id[83] & 0xc400) == 0x4400) && (id[86] & 0x0400)) {
		r.iflags.b.hob_lbal  = 1;
		r.iflags.b.hob_lbam  = 1;
		r.iflags.b.hob_lbah  = 1;
		r.lob.command = ATA_OP_READ_NATIVE_MAX_EXT;
		if (do_taskfile_cmd(fd, &r, 10)) {
			err = errno;
			//perror (" READ_NATIVE_MAX_ADDRESS_EXT failed");
		} else {
			max = (((__u64)((r.hob.lbah << 16) | (r.hob.lbam << 8) | r.hob.lbal) << 24)
				     | ((r.lob.lbah << 16) | (r.lob.lbam << 8) | r.lob.lbal)) + 1;
		}
	} else {
		r.iflags.b.dev = 1;
		r.lob.command = ATA_OP_READ_NATIVE_MAX;
		if (do_taskfile_cmd(fd, &r, timeout_12secs)) {
			err = errno;
			//perror (" READ_NATIVE_MAX_ADDRESS failed");
		} else {
			max = ((r.lob.lbah << 16) | (r.lob.lbam << 8) | r.lob.lbal) + 1;
		}
	}
	errno = err;
	return max;
}


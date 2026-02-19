#ifndef _HPA_DCO_H
#define _HPA_DCO_H

/* check_hpa_dco.c
 * Andrew Medico
 * DC3/DCCI
 * 19 September 2008
 *
 * Dervied from hdparm.c by Mark Lord
 */

__u64 get_lba_capacity (__u16 *idw);
void *get_identify_data (int fd, void *prev);
void *get_dci_data (int fd, void *prev);
__u64 get_dci_maximum_lba (__u16* dci);
__u64 do_get_native_max_sectors (int fd, __u16 *id);

#endif


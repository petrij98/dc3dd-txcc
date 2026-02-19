#!/bin/bash

source "test-helpers.sh"

if [ "$1" == "" ]
then
    echo "Usage: $0 bad_device"
    exit 1
fi

DEVICE="$1"
umount "$DEVICE"
if [ -L "$DEVICE" ]
then
    DEVICE=`readlink -f "$DEVICE"`
fi

#*************************************************************************
# These tests depend on a particular device in the possession of the 
# dc3dd developers. The reference image for this device has the bad 
# sectors replaced by runs of zeros, consistent with  dc3dd error recovery.
#*************************************************************************
REF_IMG="../../test_data/reference_images/ref-bad.img"
REF_SECTORS=8015505
REF_SECTOR_SIZE=512
BAD_SECTORS_START=4292779
BAD_SECTORS_COUNT=21

DC3DD="../src/dc3dd"
TEST_IMG="/tmp/test.img"
TEST_LOG="/tmp/test.log"

init()
{
   echo "Setting up test fixtures..."

   # Make sure device is as expected, i.e, that there are
   # BAD_SECTORS_COUNT sectors starting at BAD_SECTORS_START.
   echo "Checking device..."

   END_SECTOR=`expr $BAD_SECTORS_START + $BAD_SECTORS_COUNT`
   for ((i=$BAD_SECTORS_START; i<=$BAD_SECTORS_COUNT; i+=1))
   do
       "dd" if="$DEVICE" of="/dev/null" iflag=direct bs="$REF_SECTOR_SIZE" skip="$i" count=1
       if [ $? -eq 0 ]
       then
           echo "Expected bad sector $i is good!"
           exit 1
       fi
   done

   echo "Getting reference image size..."
   REF_IMG_BYTES=`stat -c %s "$REF_IMG"`

   echo "Getting reference image md5 hash..."
   REF_IMG_MD5_HASH=`md5sum "$REF_IMG" | cut -f 1 -d \ `

   echo "Getting reference image sha1 hash..."
   REF_IMG_SHA1_HASH=`sha1sum "$REF_IMG" | cut -f 1 -d \ `

   echo "Test fixture set up completed"
}

cleanup()
{
    # Clean up files from any previous runs.
    rm "$TEST_IMG" "$TEST_LOG" "$TEST_IMG".* "$TEST_LOG".* 
    if [ -e "$TEST_IMG" -o -e "$TEST_LOG" ]
    then
        echo "Failed to remove test output files"
        exit 1
    fi
}

check_bad_sectors_logging()
{
   #MSGCOUNT=`grep -c "at sector 2228777" "$TEST_LOG"`
   #if [ $MSGCOUNT -ne 1 ]
   #then
   #    echo "$1: log is missing or has incorrect single error message"
   #    exit 1
   #fi

   MSGCOUNT=`grep -c "from sector 4292779 to sector 4292799" "$TEST_LOG"`
   if [ $MSGCOUNT -ne 1 ]
   then
       echo "$1: log is missing or has incorrect grouped errors message"
       exit 1
   fi
}

basic()
{
   echo "Testing imaging of a device with errors..." 
   cleanup

   "$DC3DD" if="$DEVICE" of="$TEST_IMG" hash=md5 hash=sha1 log="$TEST_LOG"
   if [ $? -ne 0 ]
   then
       echo "basic: run Failed"
       exit 1
   fi

   echo "Checking results..."
   check_output_file "basic" "$TEST_IMG" "$REF_IMG_BYTES" "$REF_IMG_MD5_HASH" "$REF_IMG_SHA1_HASH"
   check_input_with_errors_logging "basic" "$TEST_LOG" "$REF_SECTOR_SIZE" "(probed)" "$REF_IMG_BYTES" "$REF_SECTORS" "$BAD_SECTORS_COUNT"
   check_input_hash_logging "basic" "$TEST_LOG" "$REF_IMG_MD5_HASH" "$REF_IMG_SHA1_HASH"
   check_single_output_logging "basic" "$TEST_LOG" "$REF_SECTORS"
   check_bad_sectors_logging "basic"
   echo "Results ok"
   echo
}

split()
{
   echo  "Testing splitting output when imaging a device with errors..." 
   cleanup

   "$DC3DD" if="$DEVICE" ofs="$TEST_IMG.000" ofsz=128M hash=md5 hash=sha1 log="$TEST_LOG" 
   if [ $? -ne 0 ]
   then
       echo "split: run failed"
       exit 1
   fi

   echo "Checking results..."
   check_split_output_file "split" "$TEST_IMG" "$REF_IMG_BYTES" "$REF_IMG_MD5_HASH" "$REF_IMG_SHA1_HASH"
   check_input_with_errors_logging "split" "$TEST_LOG" "$REF_SECTOR_SIZE" "(probed)" "$REF_IMG_BYTES" "$REF_SECTORS" "$BAD_SECTORS_COUNT"
   check_input_hash_logging "split" "$TEST_LOG" "$REF_IMG_MD5_HASH" "$REF_IMG_SHA1_HASH"
   check_single_output_logging "split" "$TEST_LOG" "$REF_SECTORS"
   check_bad_sectors_logging "split"
   echo "Results ok"
   echo
}

skip()
{
   echo "Testing input skipping on a device with errors..." 
   cleanup
   check_bad_sectors_run

   # Test skipping to the bad sectors on a device with errors,
   # using max input sectors to create only a partial image. 
   # Start by creating reference image using dd.
   "dd" if="$DEVICE" of="$TEST_IMG" conv=noerror,sync iflag=direct bs="$REF_SECTOR_SIZE" skip=4292778 count=40
   if [ $? -ne 0 ]
   then
       echo "skip: dd run failed"
       exit 1
   fi

   SKIP_REF_BYTES=`stat -c %s "$TEST_IMG"`
   SKIP_REF_MD5_HASH=`md5sum "$TEST_IMG" | cut -f 1 -d \ `
   SKIP_REF_SHA1_HASH=`sha1sum "$TEST_IMG" | cut -f 1 -d \ `

   # Get partial image from bad drive, using buffer size equal to sector size. 
   "$DC3DD" if="$DEVICE" of="$TEST_IMG" iskip=4292778 cnt=40 hash=md5 hash=sha1 bufsz="$REF_SECTOR_SIZE" log="$TEST_LOG" 
   if [ $? -ne 0 ]
   then
       echo "skip:smallbuf: run failed"
       exit 1
   fi

   echo "Checking results..."
   check_output_file "skip:smallbuf" "$TEST_IMG" "$SKIP_REF_BYTES" "$SKIP_REF_MD5_HASH" "$SKIP_REF_SHA1_HASH"
   check_input_with_errors_logging "skip:smallbuf" "$TEST_LOG" "$REF_SECTOR_SIZE" "(probed)" "$SKIP_REF_BYTES" "40" "$BAD_SECTORS_COUNT"
   check_input_hash_logging "skip:smallbuf" "$TEST_LOG" "$SKIP_REF_MD5_HASH" "$SKIP_REF_SHA1_HASH"
   check_single_output_logging "skip:smallbuf" "$TEST_LOG" "40"
   echo "Results ok"
   echo

   cleanup

   # Get partial image from bad drive, using default buffer size. 
   "$DC3DD" if="$DEVICE" of="$TEST_IMG" iskip=4292778 cnt=40 hash=md5 hash=sha1 log="$TEST_LOG"
   if [ $? -ne 0 ]
   then
       echo "skip:bigbuf: run failed"
       exit 1
   fi

   echo "Checking results..."
   check_output_file "skip:bigbuf" "$TEST_IMG" "$SKIP_REF_BYTES" "$SKIP_REF_MD5_HASH" "$SKIP_REF_SHA1_HASH"
   check_input_with_errors_logging "skip:bigbuf" "$TEST_LOG" "$REF_SECTOR_SIZE" "(probed)" "$SKIP_REF_BYTES" "40" "$BAD_SECTORS_COUNT"
   check_input_hash_logging "skip:bigbuf" "$TEST_LOG" "$SKIP_REF_MD5_HASH" "$SKIP_REF_SHA1_HASH"
   check_single_output_logging "skip:bigbuf" "$TEST_LOG" "40"
   echo "Results ok"
   echo

   cleanup

   # Test skipping into the bad sectors on a device with errors,
   # using max input sectors to create only a partial image. 
   # Start by creating reference image using dd.
   "dd" if="$DEVICE" of="$TEST_IMG" conv=noerror,sync iflag=direct bs="$REF_SECTOR_SIZE" skip=4292781 count=40
   if [ $? -ne 0 ]
   then
       echo "skip:skipbad dd run failed"
       exit 1
   fi

   SKIP_REF_BYTES=`stat -c %s "$TEST_IMG"`
   SKIP_REF_MD5_HASH=`md5sum "$TEST_IMG" | cut -f 1 -d \ `
   SKIP_REF_SHA1_HASH=`sha1sum "$TEST_IMG" | cut -f 1 -d \ `

   "$DC3DD" if="$DEVICE" of="$TEST_IMG" iskip=4292781 cnt=40 hash=md5 hash=sha1 log="$TEST_LOG"
   if [ $? -ne 0 ]
   then
       echo "skip:skipbad: run failed"
       exit 1
   fi

   echo "Checking results..."
   check_output_file "skip:skipbad" "$TEST_IMG" "$SKIP_REF_BYTES" "$SKIP_REF_MD5_HASH" "$SKIP_REF_SHA1_HASH"
   check_input_with_errors_logging "skip:skipbad" "$TEST_LOG" "$REF_SECTOR_SIZE" "(probed)" "$SKIP_REF_BYTES" "40" "`expr $BAD_SECTORS_COUNT - 2`"
   check_input_hash_logging "skip:skipbad" "$TEST_LOG" "$SKIP_REF_MD5_HASH" "$SKIP_REF_SHA1_HASH"
   check_single_output_logging "skip:skipbad" "$TEST_LOG" "40"
   echo "Results ok"
   echo
}

init
basic
split
skip
cleanup

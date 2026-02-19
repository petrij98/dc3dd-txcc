#!/bin/bash

source "test-helpers.sh"

if [ "$1" == "" ]
then
    echo "Usage: $0 good_device"
    exit 1
fi

DEVICE="$1"

#*************************************************************
# These tests depend on writing a reference image to a device
# with the sector size and size in sectors described below.
#*************************************************************
REF_IMG="../../test_data/reference_images/ref-good.img"
REF_SECTORS=1952767
REF_SECTOR_SIZE=512

DC3DD="../src/dc3dd"
TEST_IMG="/tmp/dev_img_test.img"
TEST_LOG0="/tmp/dev_img_test0.log"
TEST_LOG1="/tmp/dev_img_test1.log"

init()
{
   echo "Setting up test fixtures..."

   echo "Getting reference image size..."
   REF_IMG_BYTES=`stat -c %s "$REF_IMG"`
   echo "$REF_IMG_BYTES"   

   echo "Getting reference image md5 hash..."
   REF_IMG_MD5_HASH=`md5sum "$REF_IMG" | cut -f 1 -d \ `
   echo "$REF_IMG_MD5_HASH"   

   echo "Getting reference image sha1 hash..."
   REF_IMG_SHA1_HASH=`sha1sum "$REF_IMG" | cut -f 1 -d \ `
   echo "$REF_IMG_SHA1_HASH"   
   
   echo "Writing reference image to device..."
   umount "$DEVICE"
   if [ -L "$DEVICE" ]
   then
       DEVICE=`readlink -f "$DEVICE"`
   fi

   dd if="$REF_IMG" of="$DEVICE" 
   if [ $? -ne 0 ]
   then
       echo "failed to write reference image $REF_IMG to device $DEVICE"
       exit 1
   fi

   echo "Getting md5 hash for wipe testing..."
   PAT_MD5_HASH=`"$DC3DD" pat=00 cnt="$REF_SECTORS" | md5sum | cut -f1 -d\ `

   echo "Getting sha1 hash for wipe testing..."
   PAT_SHA1_HASH=`"$DC3DD" pat=00 cnt="$REF_SECTORS" | sha1sum | cut -f1 -d\ `

   echo "Test fixture set up completed"
}

cleanup()
{
    # Clean up files from any previous runs.
    rm "$TEST_IMG" "$TEST_LOG0" "$TEST_LOG1" 
    if [ -e "$TEST_IMG" -o -e "$TEST_LOG0" -o -e "$TEST_LOG1" ]
    then
        echo "Failed to remove test output files"
        exit 1
    fi
}

basic()
{
   echo "Testing imaging of a device with multiple logs..." 
   cleanup

   "$DC3DD" if="$DEVICE" of="$TEST_IMG" hash=md5 hash=sha1 log="$TEST_LOG0" log="$TEST_LOG1"
   if [ $? -ne 0 ]
   then
       echo "basic: run failed"
       exit 1
   fi

   echo "Checking results..."
   check_output_file "basic" "$TEST_IMG" "$REF_IMG_BYTES" "$REF_IMG_MD5_HASH" "$REF_IMG_SHA1_HASH"
   check_input_logging "basic" "$TEST_LOG0" "$REF_SECTOR_SIZE" "(probed)" "$REF_IMG_BYTES" "$REF_SECTORS" "0"
   check_input_logging "basic" "$TEST_LOG1" "$REF_SECTOR_SIZE" "(probed)" "$REF_IMG_BYTES" "$REF_SECTORS" "0"
   check_input_hash_logging "basic" "$TEST_LOG0" "$REF_IMG_MD5_HASH" "$REF_IMG_SHA1_HASH"
   check_input_hash_logging "basic" "$TEST_LOG1" "$REF_IMG_MD5_HASH" "$REF_IMG_SHA1_HASH"
   check_single_output_logging "basic" "$TEST_LOG0" "$REF_SECTORS"
   check_single_output_logging "basic" "$TEST_LOG1" "$REF_SECTORS"
   echo "Results ok"
   echo
}

wipe()
{
   echo "Testing a verified wipe of a device with zeros..."
   cleanup

   "$DC3DD" hwipe="$DEVICE" hash=md5 hash=sha1 log="$TEST_LOG0"
   if [ $? -ne 0 ]
   then
       echo "wipe: run failed"
       exit 10
   fi

   DEVICE_HASH=`md5sum "$DEVICE" | cut -f 1 -d \ `
   if [ "$DEVICE_HASH" != "$PAT_MD5_HASH" ]
   then
       echo "wipe: md5 hash mismatch"
       exit 1
   fi

   DEVICE_HASH=`sha1sum "$DEVICE" | cut -f 1 -d \ `
   if [ "$DEVICE_HASH" != "$PAT_SHA1_HASH" ]
   then
       echo "wipe: sha1 hash mismatch"
       exit 1
   fi

   echo "Checking results..."
   check_input_logging "wipe" "$TEST_LOG0" "$REF_SECTOR_SIZE" "(probed)" "$REF_IMG_BYTES" "$REF_SECTORS"
   check_input_hash_logging "wipe" "$TEST_LOG0" "$PAT_MD5_HASH" "$PAT_SHA1_HASH"
   check_single_output_logging "wipe" "$TEST_LOG0" "$REF_SECTORS"
   check_output_hash_logging "wipe" "$DEVICE" "$TEST_LOG0"
   echo "Results ok"
   echo
}

init
basic
wipe
cleanup

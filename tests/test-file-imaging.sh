#!/bin/bash

# ***************************************
# Requires mktemp and stat from coreutils
# ***************************************

source "test-helpers.sh"

DC3DD="../src/dc3dd"

REF_SECTOR_SIZE=512

REF_FILE="/tmp/ref-random-good.img"
REF_FILE_SECTORS=452767
REF_FILE_BYTES="0"
REF_FILE_MD5_HASH=""
REF_FILE_SHA1_HASH=""

REF_PAT_FILE="../../test_data/reference_images/ref-pat.img"
REF_PAT="AABBCCDD"
REF_PAT_SECTORS=12345
REF_PAT_BYTES=`stat -c %s "$REF_PAT_FILE"`
REF_PAT_MD5_HASH=`md5sum "$REF_PAT_FILE" | cut -f 1 -d \ `
REF_PAT_SHA1_HASH=`sha1sum "$REF_PAT_FILE" | cut -f 1 -d \ `

INPUT_FILE=`mktemp`

OUTPUT_FILE="/tmp/test_no_drive.img"
OUTPUT_FILE_1="/tmp/test_nodrive_o1.img"
OUTPUT_FILE_2="/tmp/test_nodrive_o2.img"
OUTPUT_FILE_3="/tmp/test_nodrive_o3.img"

LOG="/tmp/test_no_drive.log"

init()
{
   echo "Setting up test fixtures..."

    # If necessary, create reference file. 
    if [ ! -e "$REF_FILE" ]
    then
        dd if=/dev/urandom of="$REF_FILE" bs="$REF_SECTOR_SIZE" count="$REF_FILE_SECTORS"
    else
        if [ `stat -c %s "$REF_FILE"` -ne `expr $REF_FILE_SECTORS \* $REF_SECTOR_SIZE` ]
        then
            dd if=/dev/urandom of="$REF_FILE" bs="$REF_SECTOR_SIZE" count="$REF_FILE_SECTORS"
            if [ $? -ne 0 ]
            then
                echo "Failed to create reference file $REF_FILE"
                exit 1
            fi    
        fi
    fi

   # Get byte count for reference file.
   # Requires stat from coreutils.
   REF_FILE_BYTES=`stat -c %s "$REF_FILE"`

   # Get hashes of reference file.
   REF_FILE_MD5_HASH=`md5sum "$REF_FILE" | cut -f 1 -d \ `
   REF_FILE_SHA1_HASH=`sha1sum "$REF_FILE" | cut -f 1 -d \ `
    
   # Copy reference file to a file to use as test input.
   dd if="$REF_FILE" of="$INPUT_FILE" bs="$REF_SECTOR_SIZE"
   if [ $? -ne 0 ]
   then
       echo "Failed to copy reference file $REF_FILE to input file $INPUT_FILE"
       exit 1
   fi    

   echo "Test fixture set up completed"
}

cleanup()
{
   for i in "$OUTPUT_FILE" "$OUTPUT_FILE_1" "$OUTPUT_FILE_2" "$OUTPUT_FILE_3"
   do
      rm "$i" "$i".*
      if [ -e "$i" ]
      then
        echo "Failed to remove test output files"
        exit 1
      fi
   done    

   rm "$LOG"
}

basic()
{
   echo "Testing imaging a file..."
   cleanup

   "$DC3DD" if="$INPUT_FILE" of="$OUTPUT_FILE" log="$LOG" hash=md5 hash=sha1
   if [ $? -ne 0 ]
   then
       echo "basic: run failed"
       exit 1
   fi

   echo "Checking results..."
   check_output_file "basic" "$OUTPUT_FILE" "$REF_FILE_BYTES" "$REF_FILE_MD5_HASH" "$REF_FILE_SHA1_HASH"
   check_input_logging "basic" "$LOG" "$REF_SECTOR_SIZE" "(assumed)" "$REF_FILE_BYTES" "$REF_FILE_SECTORS"
   check_input_hash_logging "basic" "$LOG" "$REF_FILE_MD5_HASH" "$REF_FILE_SHA1_HASH"
   check_single_output_logging "basic" "$LOG" "$REF_FILE_SECTORS" 
   echo "Results ok"
   echo
}

split_and_join()
{
   echo "Testing splitting and joining while imaging a file..."
   cleanup

   "$DC3DD" if="$INPUT_FILE" ofs="$OUTPUT_FILE.000" log="$LOG" ofsz=100M hash=md5 hash=sha1
   if [ $? -ne 0 ]
   then
       echo "split_and_join: split run failed"
       exit 1
   fi

   echo "Checking results..."
   check_split_output_file "split_and_join" "$OUTPUT_FILE" "$REF_FILE_BYTES" "$REF_FILE_MD5_HASH" "$REF_FILE_SHA1_HASH"
   check_input_logging "split_and_join" "$LOG" "$REF_SECTOR_SIZE" "(assumed)" "$REF_FILE_BYTES" "$REF_FILE_SECTORS"
   check_input_hash_logging "split_and_join" "$LOG" "$REF_FILE_MD5_HASH" "$REF_FILE_SHA1_HASH"
   check_single_output_logging "split_and_join" "$LOG" "$REF_FILE_SECTORS"
   echo "Results ok"
   echo

   rm "$LOG"

   "$DC3DD" ifs="$OUTPUT_FILE.000" of="$OUTPUT_FILE" log="$LOG" hash=md5 hash=sha1
   if [ $? -ne 0 ]
   then
       echo "split_and_join: join run failed"
       exit 1
   fi

   echo "Checking results..."
   check_output_file "split_and_join" "$OUTPUT_FILE" "$REF_FILE_BYTES" "$REF_FILE_MD5_HASH" "$REF_FILE_SHA1_HASH"
   check_input_logging "split_and_join" "$LOG" "$REF_SECTOR_SIZE" "(assumed)" "$REF_FILE_BYTES" "$REF_FILE_SECTORS"
   check_input_hash_logging "split_and_join" "$LOG" "$REF_FILE_MD5_HASH" "$REF_FILE_SHA1_HASH"
   check_single_output_logging "split_and_join" "$LOG" "$REF_FILE_SECTORS"
   echo "Results ok"
   echo
}

interrupt()
{
   echo "Testing interrupting while imaging a file..."
   cleanup

   # NOTE: Input file needs to be big enough that the acquisition won't finish
   # before the sleep timeout expires
   set -m
   "$DC3DD" if="$INPUT_FILE" of="$OUTPUT_FILE" log="$LOG" hash=md5 hash=sha1 & pid=$!;
   sleep 1; kill -s 2 %1
   wait %1
   set +m

   echo "Checking results..."
   check_interrupted_run "interrupt" "$OUTPUT_FILE" "$LOG"
   echo "Results ok"
   echo
}

multiple_outputs()
{
   echo "Testing multiple outputs while imaging a file..."
   cleanup

   "$DC3DD" if="$INPUT_FILE" of="$OUTPUT_FILE_1" of="$OUTPUT_FILE_2" of="$OUTPUT_FILE_3" log="$LOG" hash=md5 hash=sha1
   if [ $? -ne 0 ]
   then
      echo "multiple_outputs: run failed"
      exit 1
   fi

   echo "Checking results..."
   for f in "$OUTPUT_FILE_1" "$OUTPUT_FILE_2" "$OUTPUT_FILE_3"
   do
      check_output_file "multiple_outputs" "$f" "$REF_FILE_BYTES" "$REF_FILE_MD5_HASH" "$REF_FILE_SHA1_HASH"
   done
   check_input_logging "multiple_outputs" "$LOG" "$REF_SECTOR_SIZE" "(assumed)" "$REF_FILE_BYTES" "$REF_FILE_SECTORS"
   check_input_hash_logging "multiple_outputs" "$LOG" "$REF_FILE_MD5_HASH" "$REF_FILE_SHA1_HASH"
   check_multiple_output_logging "multiple_outputs" "$LOG" "$REF_FILE_SECTORS" "3"      
   echo "Results ok"
   echo
}

multiple_split_outputs()
{
   echo "Testing multiple split outputs while imaging a file..."
   cleanup

   "$DC3DD" if="$INPUT_FILE" ofs="$OUTPUT_FILE_1.000" ofs="$OUTPUT_FILE_2.000" ofs="$OUTPUT_FILE_3.000" log="$LOG" ofsz=100M hash=md5 hash=sha1
   if [ $? -ne 0 ]
   then
      echo "multiple_split_outputs: split run failed"
      exit 1
   fi

   echo "Checking results..."
   for f in "$OUTPUT_FILE_1" "$OUTPUT_FILE_2" "$OUTPUT_FILE_3"
   do
      check_split_output_file "$FUNC_NAME" "$f" "$REF_FILE_BYTES" "$REF_FILE_MD5_HASH" "$REF_FILE_SHA1_HASH"
   done
   check_input_logging "multiple_split_outputs" "$LOG" "$REF_SECTOR_SIZE" "(assumed)" "$REF_FILE_BYTES" "$REF_FILE_SECTORS"
   check_input_hash_logging "multiple_split_outputs" "$LOG" "$REF_FILE_MD5_HASH" "$REF_FILE_SHA1_HASH"
   check_multiple_output_logging "multiple_split_outputs" "$LOG" "$REF_FILE_SECTORS" "3"     
   echo "Results ok"
   echo
}

verify_output()
{
   echo "Testing output hashing while imaging a file..."
   cleanup

   "$DC3DD" if="$INPUT_FILE" hof="$OUTPUT_FILE" hash=md5 hash=sha1 log="$LOG"
   if [ $? -ne 0 ]
   then
      echo "verify_output: run failed"
      exit 1
   fi

   echo "Checking results..."
   check_output_file "verify_output" "$OUTPUT_FILE" "$REF_FILE_BYTES" "$REF_FILE_MD5_HASH" "$REF_FILE_SHA1_HASH"
   check_input_logging "verify_output" "$LOG" "$REF_SECTOR_SIZE" "(assumed)" "$REF_FILE_BYTES" "$REF_FILE_SECTORS"
   check_input_hash_logging "verify_output" "$LOG" "$REF_FILE_MD5_HASH" "$REF_FILE_SHA1_HASH" 
   check_output_hash_logging "verify_ouput" "$OUTPUT_FILE" "$LOG"
   echo "Results ok"
   echo
}

verify_split_output()
{
   echo "Testing split output hashing while imaging a file..."
   cleanup

   "$DC3DD" if="$INPUT_FILE" hofs="$OUTPUT_FILE.000" ofsz=100M hash=md5 hash=sha1 log="$LOG"
   if [ $? -ne 0 ]
   then
      echo "verify_split_output: run failed"
      exit 1
   fi

   echo "Checking results..."
   check_split_output_file "verify_split_output" "$OUTPUT_FILE" "$REF_FILE_BYTES" "$REF_FILE_MD5_HASH" "$REF_FILE_SHA1_HASH"
   check_input_logging "verify_split_output" "$LOG" "$REF_SECTOR_SIZE" "(assumed)" "$REF_FILE_BYTES" "$REF_FILE_SECTORS"
   check_input_hash_logging "verify_split_output" "$LOG" "$REF_FILE_MD5_HASH" "$REF_FILE_SHA1_HASH"
   # MSG_COUNT=`grep -c "output hashing" "$LOG"` #for versions < 7.2.635
   MSG_COUNT=`grep -c "hashed" "$LOG"` #for versions => 7.2.635
   if [ "$MSG_COUNT" -ne "1" ]
   then
      echo "verify_output: missing final output hashing progress message"
      exit 1
   fi
   echo "Results ok"
   echo
}

count()
{
   cleanup

   ZERO_COUNT=$1
   DEF_SECTOR_SIZE=512

   "$DC3DD" if="/dev/zero" of="/dev/null" log="$LOG" cnt="$ZERO_COUNT"
   if [ $? -ne 0 ]
   then
       echo "count: imaging from /dev/zero failed"
       exit 1
   fi

   echo "Checking results..."
   BYTES=`expr $ZERO_COUNT \* $DEF_SECTOR_SIZE`
   check_input_logging "count" "$LOG" "$DEF_SECTOR_SIZE" "(assumed)" "$BYTES" "$ZERO_COUNT"
   check_single_output_logging "count" "$LOG" "$ZERO_COUNT"
   echo "Results ok"
   echo
}

counts()
{
   echo "Testing specifying max input sectors while imaging a file..."

   count       1 
   count      10 
   count     500 
   count     512 
   count    1000 
   count    1024 
   count 1000000
   count 1048576
}

pattern()
{
   echo "Testing pattern generation..."
   cleanup

   # write pattern to test image file
   "$DC3DD" tpat="$REF_PAT" of="$OUTPUT_FILE" log="$LOG" cnt="$REF_PAT_SECTORS" hash=md5 hash=sha1
   if [ $? -ne 0 ]
   then
       echo "pattern: run failed"
       exit 1
   fi

   echo "Checking results..."
   check_output_file "pattern" "$OUTPUT_FILE" "$REF_PAT_BYTES" "$REF_PAT_MD5_HASH" "$REF_PAT_SHA1_HASH"
   check_input_logging "pattern" "$LOG" "$REF_SECTOR_SIZE" "(assumed)" "$REF_PAT_BYTES" "$REF_PAT_SECTORS"
   check_input_hash_logging "pattern" "$LOG" "$REF_PAT_MD5_HASH" "$REF_PAT_SHA1_HASH"
   check_single_output_logging "pattern" "$LOG" "$REF_PAT_SECTORS" 
   echo "Results ok"
   echo
}

skip()
{
   echo "Testing input and output skipping while imaging a file..."
   cleanup

   # write four 256 byte "sectors" of zeros to a file
   "$DC3DD" ssz="256" pat="00" cnt="4" of="$OUTPUT_FILE_1" log="$LOG"
   if [ $? -ne 0 ]
   then
       echo "skip: zeros file run failed"
       exit 1
   fi

   echo "Checking results..."
   ZEROS_HALF_HASH=`md5sum "$OUTPUT_FILE_1" | cut -f 1 -d \ `
   check_input_logging "skip:zeros" "$LOG" "256" "(set)" "1024" "4"
   echo "Results ok"
   echo

   rm "$LOG"

   # write one 1024 byte "sector" of ones to a file
   "$DC3DD" ssz="1024" pat="00" cnt="1" of="$OUTPUT_FILE_2" log="$LOG"
   if [ $? -ne 0 ]
   then
       echo "skip: ones file run failed"
       exit 1
   fi

   echo "Checking results..."
   ONES_HALF_HASH=`md5sum "$OUTPUT_FILE_2" | cut -f 1 -d \ `
   BYTES=`expr 1024 \* 1`
   check_input_logging "skip:ones" "$LOG" "1024" "(set)" "1024" "1"
   echo "Results ok"
   echo

   rm "$LOG"

   # image the zeros file
   "$DC3DD" if="$OUTPUT_FILE_1" of="$OUTPUT_FILE"
   if [ $? -ne 0 ]
   then
       echo "skip: zeros file image run failed"
       exit 1
   fi

    # append the ones file to the image, skipping over the zeros as 128 byte "sectors"
    "$DC3DD" ssz="128" if="$OUTPUT_FILE_2" of="$OUTPUT_FILE" oskip="8" log="$LOG"
    if [ $? -ne 0 ]
    then
        echo "skip: concatenation run failed"
        exit 1
    fi

   echo "Checking results..."
   check_input_logging "skip:concatention" "$LOG" "128" "(set)" "1024" "8"
   echo "Results ok"
   echo

   rm "$LOG"
    
    # extract the zeros from the image as 512 byte "sectors"
   "$DC3DD" ssz="512" if="$OUTPUT_FILE" cnt="2" of="$OUTPUT_FILE_3" log="$LOG"
    if [ $? -ne 0 ]
    then
        echo "skip: extract zeros run failed"
        exit 1
    fi
    
   echo "Checking results..."
   check_input_logging "skip:extract zeros" "$LOG" "512" "(set)" "1024" "2"
   echo "Results ok"
   echo

   rm "$LOG"
    
   HALF_IMAGE_HASH=`md5sum "$OUTPUT_FILE_3" | cut -f 1 -d \ `
   if [ "$HALF_IMAGE_HASH" != "$ZEROS_HALF_HASH" ]
   then
       echo "skip: zeros half hash mismatch"
       exit 1
   fi

   # extract the ones from the image as 64 byte "sectors"
   "$DC3DD" ssz="64" if="$OUTPUT_FILE" iskip="16" of="$OUTPUT_FILE_3" log="$LOG"
   if [ $? -ne 0 ]
   then
       echo "skip: extract ones run failed"
       exit 1
   fi
    
   echo "Checking results..."
   check_input_logging "skip:extract ones" "$LOG" "64" "(set)" "1024" "16"
   echo "Results ok"
   echo

   HALF_IMAGE_HASH=`md5sum "$OUTPUT_FILE_3" | cut -f 1 -d \ `
   if [ "$HALF_IMAGE_HASH" != "$ONES_HALF_HASH" ]
   then
       echo "skip: ones half hash mismatch"
       exit 1
   fi
}

exit_messages()
{
    echo "Testing correctness of exit messages..."
    cleanup

    "$DC3DD" if="/dev/zero" cnt="1000" of="/dev/null" log="$LOG"
    if [ $? -ne 0 ]
    then
        echo "messages: /dev/zero to /dev/null run failed"
        exit 1
    fi   

    echo "Checking results..."
    LOG_VERB=`egrep "dc3dd.+?at" "$LOG" | tail -1 | awk '{print $2}'`
    if [ "$LOG_VERB" != "completed" ]
    then
        echo "messages: exit message verb  for /dev/zero to /dev/null run should be 'completed'"
        exit 2
    fi
    echo "Results ok"
    echo

    cleanup

    "$DC3DD" if="/dev/zero" cnt="1000" of="$OUTPUT_FILE" log="$LOG"
    if [ $? -ne 0 ]
    then
        echo "messages: /dev/zero to stdout run failed"
        exit 1
    fi   

    echo "Checking results..."
    LOG_VERB=`egrep "dc3dd.+?at" "$LOG" | tail -1 | awk '{print $2}'`
    if [ "$LOG_VERB" != "completed" ]
    then
        echo "messages: exit message verb for /dev/zero to stdout run should be 'completed'"
        exit 3
    fi
    echo "Results ok"
    echo

    cleanup

    "$DC3DD" if="$INPUT_FILE" of="$OUTPUT_FILE" log="$LOG"
    if [ $? -ne 0 ]
    then
        echo "messages: simple run failed"
        exit 1
    fi   

    echo "Checking results..."
    LOG_VERB=`egrep "dc3dd.+?at" "$LOG" | tail -1 | awk '{print $2}'`
    if [ "$LOG_VERB" != "completed" ]
    then
        echo "messages: exit message verb for simple run should be 'completed'"
        exit 4
    fi
    echo "Results ok"
    echo

    cleanup

    "$DC3DD" if="$INPUT_FILE" xyz="8" of="$OUTPUT_FILE" log="$LOG"

    echo "Checking results..."
    LOG_VERB=`egrep "dc3dd.+?at" "$LOG" | tail -1 | awk '{print $2}'`
    if [ "$LOG_VERB" != "aborted" ]
    then
        echo "messages: exit message verb for malformed cmd line run should be 'aborted'"
        exit 4
    fi
    echo "Results ok"
    echo

    cleanup

    set -m
    "$DC3DD" if="$INPUT_FILE" of="$OUTPUT_FILE" log="$LOG" & pid=$!;
    sleep 1; kill -s 2 %1
    wait %1
    set +m

    echo "Checking results..."
    LOG_VERB=`egrep "dc3dd.+?at" "$LOG" | tail -1 | awk '{print $2}'`
    if [ "$LOG_VERB" != "aborted" ]
    then
        echo "messages: exit message verb for interrupted run should be 'aborted'"
        exit 1
    fi
    echo "Results ok"
    echo

    cleanup

    "$DC3DD" pat="00" cnt="1000K" ofs="$OUTPUT_FILE.000" ofsz=1K log="$LOG"

    echo "Checking results..."
    LOG_VERB=`egrep "dc3dd.+?at" "$LOG" | tail -1 | awk '{print $2}'`
    if [ "$LOG_VERB" != "failed" ]
    then
        echo "messages: exit message verb for exhausted extensions run should be 'failed'"
        exit 4
    fi
    echo "Results ok"
    echo
}

validation()
{
    cleanup
    echo "Testing command line validation..."

    "$DC3DD" ifs=bar
    if [ $? -ne 1 ]
    then
        echo "Invalid ifs format not detected properly"
        exit 13
    fi

    "$DC3DD" if="$INPUT_FILE" ifs=bar.000
    if [ $? -ne 1 ]
    then
        echo "Invalid combination of if and ifs not detected properly"
        exit 13
    fi
    echo "Results ok"
    echo
}

init
basic
split_and_join
interrupt
multiple_outputs
multiple_split_outputs
verify_output
verify_split_output
counts
pattern
skip
exit_messages
validation
cleanup
rm "$INPUT_FILE"

# ***************************************
# Requires stat from coreutils
# ***************************************

#!/bin/bash

# $1 error message tag
# $2 file name
# $3 expected file size
# $4 expected md5 hash
# $5 expected sha1 hash
check_output_file()
{
   SIZE=`stat -c %s "$2"`
   if [ "$SIZE" -ne "$3" ]
   then
       echo "$1: $2 size incorrect"
       exit 1
   fi

   HASH=`md5sum "$2" | cut -f 1 -d \ `
   if [ "$HASH" != "$4" ]
   then
       echo "$1: $2 md5 hash mismatch"
       exit 1
   fi

   HASH=`sha1sum "$2" | cut -f 1 -d \ `
   if [ "$HASH" != "$5" ]
   then
       echo "$1: $2 sha1 hash mismatch"
       exit 1
   fi
}

# $1 error message tag
# $2 base file name
# $3 expected file size
# $4 expected md5 hash
# $5 expected sha1 hash
check_split_output_file()
{
   SIZE=0
   for f in "$2".*
   do
       SPLIT_SIZE=`stat -c %s "$f"`
       SIZE=`expr $SIZE + $SPLIT_SIZE`
   done
   if [ "$SIZE" -ne "$3" ]
   then
       echo "$1: $2.000 size incorrect"
       exit 1
   fi

   HASH=`cat "$2".* | md5sum | cut -f 1 -d \ `
   if [ "$HASH" != "$4" ]
   then
       echo "$1: $2.000 md5 hash mismatch"
       exit 1
   fi

   HASH=`cat "$2".* | sha1sum | cut -f 1 -d \ `
   if [ "$HASH" != "$5" ]
   then
       echo "$1: $2.000 sha1 hash mismatch"
       exit 1
   fi
}

# $1 error message tag
# $2 log file name
# $3 expected input sector size
# $4 expected input sector size source
# $5 expected input size in bytes
# $6 expected input size in sectors
check_input_logging()
{
   # Check logged sector size message. 
   LOG_SECTOR_SIZE=`grep sector\ size\: "$2" | awk '{print $3}'`
   if [ "$LOG_SECTOR_SIZE" != "$3" ]
   then
       echo "$1: wrong sector size"
       exit 1
   fi

   LOG_SECTOR_MODE=`grep sector\ size\: "$2" | awk '{print $5}'`
    if [ "$LOG_SECTOR_MODE" != "$4" ]
    then
        echo "$1: wrong sector mode"
        exit 1
    fi

   #Check logged final progress message.
   MSGCOUNT=`egrep -c bytes.+copied "$2"`
   if [ $MSGCOUNT -ne 1 ]
   then
       echo "$1: log is missing 'bytes copied' message"
       exit 1
   fi

   LOG_BYTES=`grep \)\ copied\ \( "$2" | awk '{print $1}'`
   if [ "$LOG_BYTES" != "$5" ]
   then
       echo "$1: logged bytes copied wrong"
       exit 1
   fi

   # Check logged sectors in message.
   LOG_SECTORS=`grep sectors\ in "$2" | awk '{print $1}'`
   if [ "$LOG_SECTORS" != "$6" ]
   then
       echo "$1: logged sectors in count wrong"
       exit 1
   fi
}

# $1 error message tag
# $2 log file name
# $3 expected input sector size
# $4 expected input sector size source
# $5 expected input size in bytes
# $6 expected input size in sectors
# $7 expected input bad sectors count
check_input_with_errors_logging()
{
   check_input_logging "$1" "$2" "$3" "$4" "$5" "$6"

   LOG_BAD_SECTORS=`grep bad\ sectors "$2" | awk '{print $1}'`
   if [ "$LOG_BAD_SECTORS" != "$7" ]
   then
       echo "$1: logged bad sectors count must be $7"
       exit 1
   fi
}

# $1 error message tag
# $2 log file name
# $3 expected md5 hash
# $4 expected sha1 hash
check_input_hash_logging()
{
   LOG_HASH=`grep -m 1 \(md5\) "$2" | cut -f 4 -d \ `
   if [ "$3" != "$LOG_HASH" ]
   then
       echo "$1: logged input md5 hash mismatch"
       exit 1
   fi

   LOG_HASH=`grep -m 1 \(sha1\) "$2" | cut -f 4 -d \ `
   if [ "$4" != "$LOG_HASH" ]
   then
       echo "$1: logged input sha1 hash mismatch"
       exit 1
   fi
}

# $1 error message tag
# $2 log file name
# $3 expected output file size in sectors
check_single_output_logging()
{
   # Check logged sectors out message.
   LOG_SECTORS=`grep sectors\ out "$2" | awk '{print $1}'`
   if [ "$LOG_SECTORS" != "$3" ]
   then
       echo "$1: logged sectors out count wrong"
       exit 1
   fi
}

# $1 error message tag
# $2 log file name
# $3 expected output file size in sectors
# $4 number of outputs
check_multiple_output_logging()
{
   # Check for logging of correct number of outputs
   LOG_OUTPUTS_COUNT=`grep -c sectors\ out "$LOG"`
   if [ "$LOG_OUTPUTS_COUNT" -ne "$4" ]
   then
      echo "$1: count of logged outputs is incorrect"
      exit 1
   fi

   LINE_COUNT=5
   COUNT=0
   OUTPUT="$4"
   while [ "$COUNT" != "$4" ]
   do
      LOG_SECTORS=`tail -n"$LINE_COUNT" "$LOG" | grep -m1 sectors\ out | awk '{print $1}'`
      if [ "$LOG_SECTORS" -ne "$REF_FILE_SECTORS" ]
      then
          echo "$1: logged sectors out count wrong for output $OUTPUT"
          exit 1
      fi
      COUNT=`expr $COUNT + 1`
      LINE_COUNT=`expr $COUNT + 3`
      OUTPUT=`expr $OUTPUT - 1`
   done
}

# $1 error messsage tag
# $2 output file name
# $3 log file name
check_output_hash_logging()
{
   HASH=`md5sum "$2" | cut -f1 -d \ `
   LOG_HASH=`grep "\[ok\][ ,0-9,a-z]*(md5)" "$3" | cut -f5 -d \ `
   if [ "$HASH" != "$LOG_HASH" ]
   then
       echo "$1: logged output md5 hash mismatch"
       exit 1
   fi

   HASH=`sha1sum "$2" | cut -f1 -d \ `
   LOG_HASH=`grep "\[ok\][ ,0-9,a-z]*(sha1)" "$3" | cut -f5 -d \ `
   if [ "$HASH" != "$LOG_HASH" ]
   then
       echo "$1: logged output sha1 hash mismatch"
       exit 1
   fi

   # MSG_COUNT=`grep -c "output hashing" "$3"` #for versions < 7.2.635
   MSG_COUNT=`grep -c "hashed" "$3"` #for versions => 7.2.635
   if [ "$MSG_COUNT" -ne "1" ]
   then
      echo "verify_output: missing final output hashing progress message"
      exit 1
   fi
}

# $1 error messsage tag
# $2 output file name
# $3 log file name
check_interrupted_run()
{
   # Compare output file hashes to logged input hashes.
   OUTPUT_FILE_MD5_HASH=`md5sum "$2" | cut -f 1 -d \ `
   OUTPUT_FILE_SHA1_HASH=`sha1sum "$2" | cut -f 1 -d \ `
   check_input_hash_logging "interrupt" "$3" "$OUTPUT_FILE_MD5_HASH" "$OUTPUT_FILE_SHA1_HASH"

   # Compare input and output sectors messages.
   LOG_SECTORS_IN=`grep sectors\ in "$3" | awk '{print $1}'`
   LOG_SECTORS_OUT=`grep sectors\ out "$3" | awk '{print $1}'`
   if [ "$LOG_SECTORS_IN" != "$LOG_SECTORS_OUT" ]
   then
       echo "interrupt: logged sectors in and out don't match"
       exit 1
   fi

   # Compare output file size to final progress message. 
   OUTPUT_FILE_BYTES=`stat -c %s "$2"`
   LOG_BYTES=`grep \)\ copied\ \( "$3" | awk '{print $1}'`
   if [ "$LOG_BYTES" != "$OUTPUT_FILE_BYTES" ]
   then
       echo "interrupt: logged bytes copied doesn't match output file size"
       exit 1
   fi

   # Check verb in final progress message.
   LOG_VERB=`egrep "dc3dd.+?at" "$3" | tail -1 | awk '{print $2}'`
   if [ "$LOG_VERB" != "aborted" ]
   then
      echo "interrupt: exit message verb should be 'aborted'"
      exit 1
   fi
}

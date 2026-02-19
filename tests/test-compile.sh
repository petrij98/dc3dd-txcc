#!/bin/bash

if [ "$1" != "linux" -a "$1" != "mac" ]
then
   echo "usage: $0 linux"
   echo "or"
   echo "usage: $0 mac" 
   exit 1
fi

cd ..

# dynamic link, no options

./configure
if [ $? -ne 0 ]
then
    echo "Basic configure failed"
    cd tests
    exit 1
fi

make
if [ $? -ne 0 ]
then
    echo "Basic make failed"
    cd tests
    exit 2
fi

# dynamic link, options

make distclean
if [ $? -ne 0 ]
then
    echo "Make distclean failed"
    cd tests
    exit 2
fi

./configure CFLAGS="-O2 -DDEFAULT_HASH_MD5 -DDEFAULT_HASH_SHA1 -DDEFAULT_HASH_SHA256 -DDEFAULT_HASH_SHA512 -DDEFAULT_OUTPUT_FILE_SIZE=1900M -DDEFAULT_VERBOSE_REPORTING -DDEFAULT_BASE_TEN_BYTES_REPORTING"
if [ $? -ne 0 ]
then
    echo "Flags configure failed"
    cd tests
    exit 1
fi

make
if [ $? -ne 0 ]
then
    echo "Flags make failed"
    cd tests
    exit 2
fi

for a in DEFAULT_HASH_MD5 DEFAULT_HASH_SHA1 DEFAULT_HASH_SHA256 DEFAULT_HASH_SHA512 DEFAULT_OUTPUT_FILE_SIZE DEFAULT_VERBOSE_REPORTING DEFAULT_BASE_TEN_BYTES_REPORTING
do
    MSGCOUNT=`./src/dc3dd --flags | grep -c "\<$a\>"`
    if [ $MSGCOUNT -ne 1 ]
    then
        echo "$a flag line missing"
        cd tests
        exit 3
    fi
done

LINECOUNT=`./src/dc3dd --flags | wc -l`
if [ $LINECOUNT -ne 8 ]
then
    echo "Flags line count wrong - should be 8"
    cd tests
    exit 3
fi

if [ "$1" == "linux" ]
then
   # static link, options
   # configure will fail on a mac platform 
   # since static linking is not supported
   make distclean
   if [ $? -ne 0 ]
   then
       echo "Make distclean failed"
       cd tests
       exit 2
   fi

   ./configure CFLAGS="-O2 -DDEFAULT_HASH_MD5 -DDEFAULT_HASH_SHA1 -static"
   if [ $? -ne 0 ]
   then
       echo "Configure failed (static)"
       cd tests
       exit 1
   fi

   make
   if [ $? -ne 0 ]
   then
       echo "Make failed (static)"
       cd tests
       exit 2
   fi
fi

cd tests

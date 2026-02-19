#!/bin/bash

DC3DD="../src/dc3dd"

MD5_DIR="md5_test_files"
SHA1_DIR="sha1_test_files"

find "$MD5_DIR"/* -type f | while read f
do
        h=`"$DC3DD" if="$f" of=/dev/null hash=md5 2>&1 | grep "(md5)" | awk '{print $1}'`
        b=`basename "$f"`
        o=`md5sum "$f" | awk '{print $1}'`
        if [ "$h" != "$o" ]
        then 
            echo "md5 hash mismatch for $b"
            exit 1
        else
            echo "md5 hash ok for $b"
        fi
done

find "$SHA1_DIR"/* -type f | while read f
do
        h=`"$DC3DD" if="$f" of=/dev/null hash=sha1 2>&1 | grep "(sha1)" | awk '{print $1}'`
        b=`basename "$f"`
        o=`sha1sum "$f" | awk '{print $1}'`
        if [ "$h" != "$o" ]
        then
            echo "sha1 hash mismatch for $b"
            exit 2
        else
            echo "sha1 hash ok for $b"
        fi
done


#!/bin/bash

   ./test-compile.sh linux \
&& ./test-file-imaging.sh \
&& ./test-hashing.sh  \
&& sudo ./test-device-imaging.sh /dev/disk/by-id/usb-0930_USB_Flash_Memory_04107C603292E97C-0\:0 \
&& sudo ./test-damaged-device-imaging.sh /dev/disk/by-id/usb-SanDisk_U3_Cruzer_Micro_000015EBBA630BCF-0\:0


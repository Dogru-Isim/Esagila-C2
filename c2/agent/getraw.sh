#!/bin/bash

echo -n test/loader.bin
echo

a=''

for i in $(objdump -d build/loader.exe|grep "^ " | cut -f2); do
    a=$a'0x'$i','
done

b=${a::-1}

echo 'unsigned char shellcode[] = {'
echo $b
echo '};'

echo

#!/bin/bash

echo -n test/loader.bin
echo
for i in $(objdump -d build/loader.exe|grep "^ " | cut -f2); do echo -n '\x'$i; done
echo

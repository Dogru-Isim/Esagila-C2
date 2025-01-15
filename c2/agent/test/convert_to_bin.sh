#!/bin/bash

for i in $(objdump -d loader.exe | grep "^ " |cut -f2); do echo -n '\x'$i; done; echo

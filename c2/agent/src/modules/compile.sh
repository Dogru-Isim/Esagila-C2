#!/bin/bash

if [ -z "$1" ]; then
    echo "Usage: $0 <module_name>"
    exit
elif [ "$1" = "std" ]; then
    echo "Compiling std.c"
    x86_64-w64-mingw32-gcc -shared ./src/std.c -o ../../../server/std.dll -O2
else
    echo "Unknown module name: $1"
    exit
fi

echo "Compilation successful: $1"

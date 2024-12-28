#!/bin/bash

DEBUG=0

if [ "$2" = "DEBUG" ]; then
    DEBUG=1
    echo "Debug ON"
else
    echo "Debug OFF"
fi

if [ -z "$1" ]; then
    echo "Usage: $0 <module_name>"
    exit
elif [ "$1" = "std" ]; then
    echo "Compiling std.c"
    if [[ DEBUG -eq 1 ]]; then
        x86_64-w64-mingw32-gcc -DDEBUG -shared ./src/std.c ./src/injections.c -o ../../../server/std.dll -O2
    else
        x86_64-w64-mingw32-gcc -shared ./src/std.c ./src/injections.c -o ../../../server/std.dll -O2
    fi
else
    echo "Unknown module name: $1"
    exit
fi

echo "Compilation successful: $1"

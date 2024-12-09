x86_64-w64-mingw32-gcc -shared std.c -o std.dll -O2 -Wl,--out-implib,std.lib && mv std.dll ../../server/std.dll

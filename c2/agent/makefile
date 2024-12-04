make:
	nasm -f win64 adjuststack.asm -o adjuststack.o
	#x86_64-w64-mingw32-gcc loader.c -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o loader.o -Wl,-Tlinker.ld,--no-seh -g
	x86_64-w64-mingw32-gcc loader.c -DDEBUG -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o loader.o -Wl,-Tlinker.ld,--no-seh
	x86_64-w64-mingw32-ld -s adjuststack.o loader.o -o /mnt/vshare/loader.exe
	rm shellcode.bin adjuststack.o

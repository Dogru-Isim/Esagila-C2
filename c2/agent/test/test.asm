; compile with
; nasm -f win64 test.asm -o test.o
; x86_64-w64-mingw32-ld test.o -o test.exe

Global Start

Start:
    incbin "loader2.bin"

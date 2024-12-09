DEBUG_DEFAULT = 0  # Disabled
DEBUG ?= $(DEBUG_DEFAULT)

OUT_PATH_DEFAULT ?= ./build/loader.exe
OUT_PATH ?= $(OUT_PATH_DEFAULT)

make:
	nasm -f win64 ./src/adjuststack.asm -o ./tmp/adjuststack.o
ifeq ($(DEBUG), $(DEBUG_DEFAULT))  # if DEBUG isn't overridden by the user
	@echo "\nDEBUG DISABLED\n"
	x86_64-w64-mingw32-gcc ./src/loader.c -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o ./tmp/loader.o -Wl,-T./src/linker.ld,--no-seh -g
else
	@echo "\nDEBUG ENABLED\n"
	x86_64-w64-mingw32-gcc ./src/loader.c -DDEBUG -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -o ./tmp/loader.o -Wl,-T./src/linker.ld,--no-seh
endif
	x86_64-w64-mingw32-ld -s ./tmp/adjuststack.o ./tmp/loader.o -o $(OUT_PATH)
	rm ./tmp/adjuststack.o ./tmp/loader.o
	@echo "\nExecutable created at $(OUT_PATH)\n"


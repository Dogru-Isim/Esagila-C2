#SERVER_M = SERVER='1','9','2','.','1','6','8','.','0','.','1',0
#PORT_M = PORT=5001
#UUID_M = UUID='1','1','e','3','b','2','7','c','-','a','1','e','7','-','4','2','2','4','-','b','4','d','9','-','3','a','f','3','6','f','a','2','f','0','d','0',0

DEBUG_DEFAULT = 0  # Disabled
DEBUG ?= $(DEBUG_DEFAULT)

OUT_PATH_DEFAULT ?= ./build/loader.exe
OUT_PATH ?= $(OUT_PATH_DEFAULT)

CFLAGS = -fPIC -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -Wl,-T./src/linker.ld,--no-seh
CFLAGS_D = -DDEBUG -fPIC -Wall -m64 -ffunction-sections -fno-asynchronous-unwind-tables -nostdlib -fno-ident -O2 -c -Wl,-T./src/linker.ld,--no-seh -g

make:
	nasm -f win64 ./src/adjuststack.asm -o ./tmp/adjuststack.o
ifeq ($(DEBUG), $(DEBUG_DEFAULT))  # if DEBUG isn't overridden by the user
	@echo "\nDEBUG DISABLED\n"
	x86_64-w64-mingw32-gcc ./src/std.c $(CFLAGS) -o ./tmp/std.o
	x86_64-w64-mingw32-gcc ./src/http.c $(CFLAGS) -DSERVER_M=$(SERVER_M) -DPORT_M=$(PORT_M) -DUUID_M=$(UUID_M) -o ./tmp/http.o
	x86_64-w64-mingw32-gcc ./src/addresshunter.c $(CFLAGS) -DSERVER_M -DPORT_M -DUUID_M -o ./tmp/addresshunter.o
	x86_64-w64-mingw32-gcc ./src/tokenizer.c $(CFLAGS) -DSERVER_M -DPORT_M -DUUID_M -o ./tmp/tokenizer.o
	x86_64-w64-mingw32-gcc ./src/json.c $(CFLAGS) -DSERVER_M -DPORT_M -DUUID_M -o ./tmp/json.o
	x86_64-w64-mingw32-gcc ./src/loader.c $(CFLAGS) -DSERVER_M=$(SERVER_M) -DPORT_M=$(PORT_M) -DUUID_M=$(UUID_M) -o ./tmp/loader.o
else
	@echo "\nDEBUG ENABLED\n"
	x86_64-w64-mingw32-gcc ./src/std.c $(CFLAGS_D) -o ./tmp/std.o
	x86_64-w64-mingw32-gcc ./src/http.c $(CFLAGS_D) -DSERVER_M=$(SERVER_M) -DPORT_M=$(PORT_M) -DUUID_M=$(UUID_M) -o ./tmp/http.o
	x86_64-w64-mingw32-gcc ./src/addresshunter.c $(CFLAGS_D) -DSERVER_M -DPORT_M -DUUID_M -o ./tmp/addresshunter.o
	x86_64-w64-mingw32-gcc ./src/tokenizer.c $(CFLAGS_D) -DSERVER_M -DPORT_M -DUUID_M -o ./tmp/tokenizer.o
	x86_64-w64-mingw32-gcc ./src/json.c $(CFLAGS_D) -DSERVER_M -DPORT_M -DUUID_M -o ./tmp/json.o
	x86_64-w64-mingw32-gcc ./src/loader.c $(CFLAGS_D) -DSERVER_M=$(SERVER_M) -DPORT_M=$(PORT_M) -DUUID_M=$(UUID_M) -o ./tmp/loader.o
endif
	x86_64-w64-mingw32-ld -s ./tmp/adjuststack.o ./tmp/std.o ./tmp/http.o ./tmp/addresshunter.o ./tmp/tokenizer.o ./tmp/json.o ./tmp/loader.o -o $(OUT_PATH)
	rm ./tmp/adjuststack.o ./tmp/loader.o ./tmp/std.o ./tmp/http.o ./tmp/addresshunter.o ./tmp/tokenizer.o ./tmp/json.o
	@echo "\nExecutable created at $(OUT_PATH)\n"

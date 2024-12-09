#ifndef ADDRESSHUNTER_H
#define ADDRESSHUNTER_H

#include <inttypes.h>
#include <windows.h>
#include "typedefs.h"

#define DLL_QUERY_HMODULE 6
#define KERNEL32DLL_HASH 0x6A4ABC5B

// main hashing function for ror13
__forceinline DWORD ror13(DWORD d) { return _rotr(d, 13); }

__forceinline DWORD hash(char *c) {
    DWORD h = 0;
    do {
        h = ror13(h);
        h += *c;
    }
    while (*++c);

    return h;
}

// function to fetch the base address of kernel32.dll from the Process
// Environment Block
UINT64 GetKernel32();

UINT64 GetSymbolAddress(HANDLE hModule, LPCSTR lpProcName);

DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress);

UINT_PTR GetRLOffset(PAPI api, PVOID lpDll);

#endif  // ADDRESSHUNTER_H

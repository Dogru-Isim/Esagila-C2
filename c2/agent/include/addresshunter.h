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

/*
This function fetches the base address of kernel32.dll from the Process Environment Block

Input:
    The function takes no input
Output:
    Success -> UINT64: a pointer to kernel32.dll
    Failure -> 0
*/
UINT64 GetKernel32();

/*
This function extracts the address of a function from a DLL using the function's name.
It does so using the export directory of the DLL

Input:
    [in] HANDLE hModule: a handle to the DLL
    [in] LPCSTR lpProcName: the function name
Output:
    Success                -> UINT64: a pointer to the function
    hModule is NULL        -> 0
    cannot find lpProcName -> 0
*/
UINT64 GetSymbolAddress(HANDLE hModule, LPCSTR lpProcName);

/*
This function converts an RVA relative to the preferred base address of a DLL into an
offset changing uiBaseAddress (real location of the DLL in memory) as the base.

The reason is that if an RVA in a DLL is relative to the preferred base addres the RVA becomes
unusable if the DLL cannot be not loaded into the preferred address
The output from this function can be used to summarize with uiBaseAddress to get the address 
pointed to by dwRva -assuming uiBaseAddress is not relative.

Input:
    [in] DWORD dwRva: a virtual address obtained from a DLL
    [in] UINT_PTR uiBaseAddress: the current address of the DLL in memory
Output:
    Success -> DWORD: the real location dwRva was meant to point to
    Failure -> 0
*/
DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress);

/*
This function gets the offset of a function called ReflectiveLoader from a DLLs export table
the offset is relative to the DLLs current address

Input:
    [in] PAPI api: a struct that stores a pointer to the `wprintf` function for debugging
    [in] PVOID lpDll: a pointer to the DLL from which to get a pointer to the reflective loader's
Output:
    Success -> UINT_PTR: the offset of the reflective loader
    Failure -> 0
*/
UINT_PTR GetRLOffset(PAPI api, PVOID lpDll);

#endif  // ADDRESSHUNTER_H

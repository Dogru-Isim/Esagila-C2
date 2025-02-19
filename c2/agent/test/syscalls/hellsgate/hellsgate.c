#include "../../../include/typedefs.h"
#include <windows.h>
#include <stdio.h>
#include <ntdef.h>
// #include <winternl.h>  // interesting header file that has low level structs like IO_STATUS_BLOCK, PEB, PEB_LDR_DATA, UNICODE_STRING...

int stdStrCmpW(const wchar_t *str1, const wchar_t *str2) {
    while (*str1 && (*str1 == *str2)) {
        str1++;
        str2++;
    }
    return *(wchar_t *)str1 - *(wchar_t *)str2;
}

int stdStrCmpA(const char *str1, const char *str2) {
    while (*str1 && (*str1 == *str2)) {
        str1++;
        str2++;
    }
    return *(char *)str1 - *(char *)str2;
}

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
UINT64 GetSymbolAddress(HANDLE hModule, LPCSTR lpProcName)
{
    UINT64 dllAddress = (UINT64)hModule, symbolAddress = 0, exportedAddressTable = 0, namePointerTable = 0, ordinalTable = 0;

    if (hModule == NULL) { return 0; }

    PIMAGE_NT_HEADERS ntHeaders = NULL;
    PIMAGE_DATA_DIRECTORY dataDirectory = NULL;
    PIMAGE_EXPORT_DIRECTORY exportDirectory = NULL;

    // Export the function from .edata ( IMAGE_EXPORT_DIRECTORY) by name
    // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-edata-section-image-only

    // get a pointer to IMAGE_NT_HEADERS
    ntHeaders = (PIMAGE_NT_HEADERS)(dllAddress + ((PIMAGE_DOS_HEADER)dllAddress)->e_lfanew);
    // get a pointer to a IMAGE_DATA_DIRECTORY whose member `VirtualAddress` points to the IMAGE_EXPORT_DIRECTORY (.edata section)
    dataDirectory = (PIMAGE_DATA_DIRECTORY)&ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    // get the IMAGE_EXPORT_DIRECTORY (.edata section) using the VirtualAddress member
    exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dllAddress + dataDirectory->VirtualAddress);

    // get a pointer to the array of addresses that point to functions
    exportedAddressTable = (dllAddress + exportDirectory->AddressOfFunctions);
    // get a pointer to the array of addresses that point to function names
    namePointerTable = (dllAddress + exportDirectory->AddressOfNames);
    // get a pointer to the array of ordinal values
    ordinalTable = (dllAddress + exportDirectory->AddressOfNameOrdinals);

    // is the value an ordinal?
    if (((UINT64)lpProcName & 0xFFFF0000) == 0x00000000)
    {
        exportedAddressTable += ((IMAGE_ORDINAL((UINT64)lpProcName) - exportDirectory->Base) * sizeof(DWORD));
        symbolAddress = (UINT64)(dllAddress + DEREF_32(exportedAddressTable));
    }
    else
    {
        DWORD dwCounter = exportDirectory->NumberOfNames;
        while (dwCounter--)
        {
            char *cpExportedFunctionName = (char *)(dllAddress + DEREF_32(namePointerTable));
            if (stdStrCmpA(cpExportedFunctionName, lpProcName) == 0)
            {
                exportedAddressTable += (DEREF_16(ordinalTable) * sizeof(DWORD));
                symbolAddress = (UINT64)(dllAddress + DEREF_32(exportedAddressTable));
                break;
            }
            // From the MSDN:
            // these two arrays are positionally correspondent
            // the name pointer table and the ordinal table must have the same number of members. Each ordinal is an index into the export address table.
            namePointerTable += sizeof(DWORD);
            ordinalTable += sizeof(WORD);
        }
    }

    return symbolAddress;
}

/* ========================================================================== Hell's Gate ========================================================================== */

typedef SIZE_T SSN;

typedef struct _Win32Func
{
    LPVOID baseAddress;
    SSN syscallNumber;
    PSTR functionName;
} Win32Func, *PWin32Func;

typedef struct _Win32Api
{
    Win32Func ZwWriteVirtualMemory;
} Win32Api, *PWin32Api;

/*
 * Win32Func hellsGateFuncGet
 *
 * @brief Construct a Win32Func using the provided parameters
 *
 * Fetch the syscall used to execute the provided ntdll function by walking the export table of ntdll.dll
 * using the `GetSymbolAddress` function and retrieving the fourth byte from the base address of the function.
 * functionBaseAddress + sizeof(CHAR)*4 = syscallForTheFunction (ex. NtWriteVirtualMemory = 0x3A)
 *
 * @param HANDLE hNtdll: pointer to ntdll.dll
 * @param PSTR functionName: name of the function
 *
 * @return Win32Func: a Win32Function constructed using the parameters
 *
 */
Win32Func hellsGateFuncGet(HANDLE hNtdll, PSTR functionName)
{
    Win32Func win32Func;
    win32Func.baseAddress = (LPVOID)GetSymbolAddress(hNtdll, functionName);
    win32Func.functionName = functionName;
    win32Func.syscallNumber = ((CHAR*)win32Func.baseAddress)[4];  // baseAddress + sizeof(CHAR)*4 = syscall number
    
    return win32Func;
}

//extern void hellsGateFuncExecute(SSN syscallNumber, SIZE_T numberOfParams, ...);

/* ======================================================================== End Hell's Gate ======================================================================== */

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR cmdline, int nShowCmd)
{
    _PPEB pPeb = (_PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA pPebLdrData = (PPEB_LDR_DATA) ((UINT_PTR)pPeb->pLdr);
    //PPEB_LDR_DATA pPebLdrData = (PPEB_LDR_DATA) ((UINT_PTR)pPeb->Ldr - 16);

    PLIST_ENTRY pLdrDataTableEntry = (PLIST_ENTRY)(pPebLdrData->InMemoryOrderModuleList).Flink;

    PWSTR dllName = NULL;
    USHORT usCounter = 0;
    DWORD ror13Hash = 0;
    UINT_PTR uiNtdll = 0;

    dllName = (PWSTR)((PLDR_DATA_TABLE_ENTRY)pLdrDataTableEntry)->BaseDllName.pBuffer;

    while (((PLDR_DATA_TABLE_ENTRY)pLdrDataTableEntry)->DllBase)
    {
        dllName = (PWSTR)((PLDR_DATA_TABLE_ENTRY)pLdrDataTableEntry)->BaseDllName.pBuffer;
        usCounter = ((PLDR_DATA_TABLE_ENTRY)pLdrDataTableEntry)->BaseDllName.Length;

        //if (stdStrCmpW(dllName, (WCHAR[]){ L'K', L'E', L'R', L'N', L'E', L'L', L'3', L'2', L'.', L'D', L'L', L'L', 0}) == 0)
        if (stdStrCmpW(dllName, (WCHAR[]){ L'n', L't', L'd', L'l', L'l', L'.', L'd', L'l', 'l', 0}) == 0)
        {
            uiNtdll = (UINT_PTR) ((PLDR_DATA_TABLE_ENTRY)pLdrDataTableEntry)->DllBase;
            printf("%S: %p\n", (WCHAR*)((PLDR_DATA_TABLE_ENTRY)pLdrDataTableEntry)->BaseDllName.pBuffer, (LPVOID)uiNtdll);
            break;
        }
        pLdrDataTableEntry = pLdrDataTableEntry->Flink;
    }

    //UINT64 zwWriteVirtualMemory = GetSymbolAddress((HANDLE)uiNtdll, "ZwWriteVirtualMemory");
    //printf("ZwWriteVirtualMemory: 0x%x\n", ((CHAR*)zwWriteVirtualMemory)[4]);

    /* ==================================================== Execute ZwWriteVirtualMemory ==================================================== */

    extern void _hellsGateSyscallProvide(SSN syscallNumber);
    extern void _hellsGateSyscallRun(PVOID param1, ...);

    Win32Func zwWriteVirtualMemory = hellsGateFuncGet((HANDLE)uiNtdll, "ZwWriteVirtualMemory");

    PVOID baseAddress;
    CONST DWORD allocNum = 6;
    DWORD numberOfBytesWritten = 0;
    baseAddress = VirtualAlloc(NULL, allocNum, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    /*
    printf("GetCurrentProcess(): %p\n", GetCurrentProcess());
    printf("baseAddress %p\n", baseAddress);
    char* hello = "Hello";
    printf("hello: %p\n", hello);
    printf("pNumberOfBytesWritten: %p\n", pNumberOfBytesWritten);
    hellsGateFuncExecute(zwWriteVirtualMemory.syscallNumber, zwWriteVirtualMemory.numberOfParams, GetCurrentProcess(), baseAddress, hello, allocNum, pNumberOfBytesWritten);
    */

    _hellsGateSyscallProvide(zwWriteVirtualMemory.syscallNumber);  // NtWriteVirtualMemory
    _hellsGateSyscallRun(GetCurrentProcess(), baseAddress, "Hello", allocNum, &numberOfBytesWritten);

    printf("Written data: %s\n",(CHAR*)baseAddress);

    /* ====================================================== End ZwWriteVirtualMemory ====================================================== */

    /* ======================================================== Execute ZwCreateFile ======================================================== */

/*
    Win32Func zwCreateFile = hellsGateFuncGet((HANDLE)uiNtdll, "ZwCreateFile", 11);

    printf("Base ZwCreateFile: %p\n", zwCreateFile.baseAddress);
    printf("First opcode ZwCreateFile: 0x%x\n", ((CHAR*)zwCreateFile.baseAddress)[0]);
    printf("SSN ZwCreateFile: 0x%x\n", zwCreateFile.syscallNumber);
    printf("Number of Params ZwCreateFile: %x\n", zwCreateFile.numberOfParams);

    typedef struct _IO_STATUS_BLOCK {
        __C89_NAMELESS union {
        NTSTATUS Status;
        PVOID Pointer;
        };
        ULONG_PTR Information;
    } IO_STATUS_BLOCK,*PIO_STATUS_BLOCK;

    typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
    } UNICODE_STRING, *PUNICODE_STRING;

    HANDLE hFile;
    OBJECT_ATTRIBUTES objectAttributes;
    UNICODE_STRING fileName;
    IO_STATUS_BLOCK ioStatusBlock;
    InitializeObjectAttributes(&objectAttributes, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    hellsGateFuncExecute(zwCreateFile.syscallNumber, zwCreateFile.numberOfParams, hFile, FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES, objectAttributes, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_CREATE, FILE_NON_DIRECTORY_FILE, NULL, 0);
*/

    /* ========================================================== End ZwCreateFile ========================================================== */

    return 0;
}


#include "../../include/typedefs.h"

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

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR cmdline, int nShowCmd)
{
    extern int printf (const char *__format, ...);

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

    UINT64 zwWriteVirtualMemory = GetSymbolAddress((HANDLE)uiNtdll, "ZwWriteVirtualMemory");

    // get syscall number from offset 4
    printf("ZwWriteVirtualMemory: 0x%x\n", ((CHAR*)zwWriteVirtualMemory)[4]);

    return 0;
}


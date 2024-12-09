#include "../include/std.h"
#include "../include/addresshunter.h"

// function to fetch the base address of kernel32.dll from the Process
// Environment Block
UINT64 GetKernel32() {
    ULONG_PTR kernel32dll, Flink, pDllName, ror13Hash;
    USHORT usCounter;

    // kernel32.dll is at 0x60 offset and __readgsqword is compiler intrinsic,
    // so we don't need to extract it's symbol
    // NOTE: Although it's mentioned in MSDN that every Flink points to a LDR_DATA_TABLE_ENTRY, i still don't understand how casting a Flink (a LIST_ENTRY according to msdn) to PLDR_DATA_TABLE_ENTRY works.
    // https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data
    // TODO: improve naming of kernel32dll (first is pPeb, second is pLdr, third is pKernel32Dll)
    kernel32dll = __readgsqword(0x60);

    kernel32dll = (ULONG_PTR)((_PPEB)kernel32dll)->pLdr;
    Flink = (ULONG_PTR)((PPEB_LDR_DATA)kernel32dll)->InMemoryOrderModuleList.Flink;
    while (Flink)
    {
        pDllName = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)Flink)->BaseDllName.pBuffer;
        usCounter = ((PLDR_DATA_TABLE_ENTRY)Flink)->BaseDllName.Length;
        ror13Hash = 0;

        // calculate the hash of kernel32.dll (0x6A4ABC5B)
        do {
            ror13Hash = ror13((DWORD)ror13Hash);  // rotate right 13. Convert string values into decimal representations
            if (*((BYTE *)pDllName) >= 'a')
            {
                // if character pointed to by pDllName is lowercase,
                // convert it into uppercase by subtracting 0x20
                ror13Hash += *((BYTE *)pDllName) - 0x20;
            }
            else
            {
                ror13Hash += *((BYTE *)pDllName);
            }
            pDllName++;
        }
        while (--usCounter);

        // compare the hash kernel32.dll
        // 0x6A4ABC5B
        if ((DWORD)ror13Hash == KERNEL32DLL_HASH)
        {
            // return kernel32.dll if found
            kernel32dll = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)Flink)->DllBase;
            return kernel32dll;
        }
        Flink = DEREF(Flink);  // dereference Flink (Flink) to get the next LDR_DATA_TABLE_ENTRY
    }
    return 0;
}

UINT64 GetSymbolAddress(HANDLE hModule, LPCSTR lpProcName)
{
    UINT64 dllAddress = (UINT64)hModule, symbolAddress = 0, exportedAddressTable = 0, namePointerTable = 0, ordinalTable = 0;

    if (hModule == NULL) { return 0; }

    PIMAGE_NT_HEADERS ntHeaders = NULL;
    PIMAGE_DATA_DIRECTORY dataDirectory = NULL;
    PIMAGE_EXPORT_DIRECTORY exportDirectory = NULL;

    ntHeaders = (PIMAGE_NT_HEADERS)(dllAddress + ((PIMAGE_DOS_HEADER)dllAddress)->e_lfanew);
    dataDirectory = (PIMAGE_DATA_DIRECTORY)&ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    exportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dllAddress + dataDirectory->VirtualAddress);

    exportedAddressTable = (dllAddress + exportDirectory->AddressOfFunctions);
    namePointerTable = (dllAddress + exportDirectory->AddressOfNames);
    ordinalTable = (dllAddress + exportDirectory->AddressOfNameOrdinals);

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
            if (my_strcmp(cpExportedFunctionName, lpProcName) == 0)
            {
                exportedAddressTable += (DEREF_16(ordinalTable) * sizeof(DWORD));
                symbolAddress = (UINT64)(dllAddress + DEREF_32(exportedAddressTable));
                break;
            }
            namePointerTable += sizeof(DWORD);
            ordinalTable += sizeof(WORD);
        }
    }

    return symbolAddress;
}


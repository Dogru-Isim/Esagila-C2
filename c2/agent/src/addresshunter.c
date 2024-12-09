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

DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress)
{
    WORD wIndex = 0;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;

    pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

    pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

    if (dwRva < pSectionHeader[0].PointerToRawData)
    { return dwRva; }

    for (wIndex = 0; wIndex < pNtHeaders->FileHeader.NumberOfSections; wIndex++)
    {
        if (dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData))
        { return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData); }
    }

    return 0;
}

UINT_PTR GetRLOffset(PAPI api, PVOID lpDll)
{
    WCHAR rlName[] = { 'R', 'e', 'f', 'l', 'e', 'c', 't', 'i', 'v', 'e', 'L', 'o', 'a', 'd', 'e', 'r', 0 };

    UINT_PTR uiDll = (UINT_PTR)lpDll;
    #ifdef DEBUG
    WCHAR uiDllFormat[] = { 'd', 'l', 'l', 'A', 'd', 'd', 'r', 'e', 's', 's', ':', ' ', '%', 'p', '\n', 0 };
    ((WPRINTF)api->wprintf)(uiDllFormat, uiDll);
    #endif

    UINT_PTR uiNtHeaders;
    UINT_PTR uiExportDirectoryData;

    uiNtHeaders = uiDll + ((PIMAGE_DOS_HEADER)uiDll)->e_lfanew;
    #ifdef DEBUG
    WCHAR ntHeaders[] = { 'n', 't', 'h', 'e', 'a', 'd', 'e', 'r', 's', ':', ' ', '%', 'p', '\n', 0 };
    ((WPRINTF)api->wprintf)(ntHeaders, uiNtHeaders);
    #endif

    uiExportDirectoryData = (UINT_PTR) &((PIMAGE_NT_HEADERS64)uiNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    UINT_PTR uiExportDirectory = uiDll + Rva2Offset(((PIMAGE_DATA_DIRECTORY)uiExportDirectoryData)->VirtualAddress, uiDll);
    #ifdef DEBUG
    WCHAR pExportDir[] = { 'e', 'x', 'p', 'o', 'r', 't', 'd', 'i', 'r', ':', ' ', '%', 'p', '\n', 0 };
    ((WPRINTF)api->wprintf)(pExportDir, uiExportDirectory);
    #endif

    DWORD uiExportDirectorySize = ((PIMAGE_DATA_DIRECTORY)uiExportDirectoryData)->Size;
    #ifdef DEBUG
    WCHAR pExportDirSize[] = { 'e', 'x', 'p', 'o', 'r', 't', 's', 'i', 'z', 'e', ':', ' ', '%', 'd', '\n', 0 };
    ((WPRINTF)api->wprintf)(pExportDirSize, uiExportDirectorySize);
    #endif

    DWORD dwNumberOfEntries;
    UINT_PTR functionNameAddresses;
    UINT_PTR functionOrdinals;
    UINT_PTR functionAddresses;
    UINT_PTR rlAddress = 0;

    dwNumberOfEntries = ((PIMAGE_EXPORT_DIRECTORY)uiExportDirectory)->NumberOfNames;
    #ifdef DEBUG
    CHAR entries[] = { 'e', 'n', 't', 'r', 'i', 'e', 's', ':', ' ', '%', 'd', '\n', 0 };
    ((PRINTF)api->printf)(entries, dwNumberOfEntries);
    #endif

    // NOTE: ExportDirectory->AddressOf... gives an address to an array //
    // but the address is relative to the DLL base which is the address //
    // in the DLL's NT header(?). This address is the preferred address //
    // but is not always the real location the DLL is located in memory //
    // Therefore, the following struct members don't return values that //
    // we can use as is. However, we can calculate their offsets to the //
    // DLL's current location and then add the offsets to DLL's current //
    // address. I *believe* reading the base address from the NT header //
    // and adding the relative virtual address to it would work as well //
    // However, I am not sure if it actually would as I did not test it //
    functionNameAddresses = uiDll + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDirectory)->AddressOfNames, uiDll);
    functionOrdinals = uiDll + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDirectory)->AddressOfNameOrdinals, uiDll);
    functionAddresses = uiDll + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDirectory)->AddressOfFunctions, uiDll);

    CHAR* exportedFunctionName = {0};
    while(dwNumberOfEntries--)
    {
        exportedFunctionName = (CHAR*)(uiDll + Rva2Offset(DEREF(functionNameAddresses), uiDll));
        if (my_strcmp(exportedFunctionName, (CHAR*)rlName) == 0)
        {
            #ifdef DEBUG
            CHAR error1[] = { 'R', 'L', ' ', 'N', 'o', 't', ' ', 'F', 'o', 'u', 'n', 'd', 0 };
            ((MESSAGEBOXA)api->MessageBoxA)(0, error1, error1, 0x0L);
            #endif

            functionNameAddresses += sizeof(DWORD); // 32 bit pointers
            functionOrdinals += sizeof(WORD);       // Ordinal values or 16 bit
            continue;
        }
        else
        {
            #ifdef DEBUG
            CHAR hm[] = { 'F', 'o', 'u', 'n', 'd', ' ', 'R', 'L', 0 };
            ((MESSAGEBOXA)api->MessageBoxA)(0, hm, hm, 0x0L);
            #endif
            // Get the index from the ordinal table, multiply by the size
            // of how big one address in the function address table is.
            // This will give us the number to add to the pointer to
            // `functionAddresses` to get the offset to the RL.
            // Remember, this offset is from the reflective DLL's current
            // address. It will be used to pass to CreateThread as it's
            // fourth parameter (thread s tarting point) //
            functionAddresses += DEREF_16(functionOrdinals) * sizeof(DWORD);
            rlAddress = Rva2Offset(DEREF_32(functionAddresses), uiDll);
            break;
        }
    }

    if (rlAddress)
    { return rlAddress; }
    else
    { return 0; }
}


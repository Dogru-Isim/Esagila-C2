#include "../include/std.h"
#include "../include/addresshunter.h"

/*
This function fetches the base address of kernel32.dll from the Process Environment Block

Input:
    The function takes no input

Output:
    Success -> UINT64: a pointer to kernel32.dll

    Failure -> 0
*/
UINT64 GetKernel32() {
    ULONG_PTR kernel32dll, Flink, pDllName, ror13Hash;
    USHORT usCounter;

    // NOTE: Although it's mentioned in MSDN that every Flink points to a LDR_DATA_TABLE_ENTRY, i still don't understand how casting a Flink (a LIST_ENTRY according to msdn) to PLDR_DATA_TABLE_ENTRY works.
    // https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb_ldr_data
    // TODO: improve naming of kernel32dll (first is pPeb, second is pLdr, third is pKernel32Dll)

    // PEB is at 0x60 offset and __readgsqword is compiler intrinsic,
    // so we don't need to obtain __readgsqword() from anywhere
    kernel32dll = __readgsqword(0x60);                                               // get a pointer to the PEB structure
    kernel32dll = (ULONG_PTR)((_PPEB)kernel32dll)->pLdr;                             // get a pointer to the PEB_LDR_DATA structure
    Flink = (ULONG_PTR)((PPEB_LDR_DATA)kernel32dll)->InMemoryOrderModuleList.Flink;  // get the first forward link

    // Iterate through Flinks
    while (Flink)
    {
        pDllName = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)Flink)->BaseDllName.pBuffer;  // get the name of the DLL
        usCounter = ((PLDR_DATA_TABLE_ENTRY)Flink)->BaseDllName.Length;             // get the length of the name
        ror13Hash = 0;                                                              // ror13Hash is used to compare the ror13 hash of a DLL's name to the ror13 hash of "KERNEL32.DLL" (0x6A4ABC5B)

        // calculate the ror13 hash of pDllName
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

        // is the hash of the DLL equal to that of KERNEL32.DLL's (0x6A4ABC5B)
        if ((DWORD)ror13Hash == KERNEL32DLL_HASH)
        {
            // return the address of KERNEL32.DLL
            kernel32dll = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)Flink)->DllBase;
            return kernel32dll;
        }
        Flink = DEREF(Flink);  // dereference Flink (Flink) to get the next LDR_DATA_TABLE_ENTRY
    }
    return 0;  // KERNEL32.DLL cannot be found
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
            if (my_strcmp(cpExportedFunctionName, lpProcName) == 0)
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
DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress)
{
    WORD wIndex = 0;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;

    // get the IMAGE_NT_HEADERS struct
    pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

    // get the IMAGE_SECTION_HEADER struct
    pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

    // TODO: Understand why this check is necessary and why to return dwRva
    if (dwRva < pSectionHeader[0].PointerToRawData)
    { return dwRva; }

    for (wIndex = 0; wIndex < pNtHeaders->FileHeader.NumberOfSections; wIndex++)
    {
        if (dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData))
        { return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData); }
    }

    return 0;
}

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
UINT_PTR GetRLOffset(PAPI api, PVOID lpDll)
{
    // name of the reflective loader
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

    // get a pointer to the IMAGE_DATA_DIRECTORY
    uiExportDirectoryData = (UINT_PTR) &((PIMAGE_NT_HEADERS64)uiNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    // convert the RVA relative to the preferred base address to an offset relative to the DLLs current address (uiDll)
    // adding that value to uiDll gives us the address of the IMAGE_EXPORT_DIRECTORY
    UINT_PTR uiExportDirectory = uiDll + Rva2Offset(((PIMAGE_DATA_DIRECTORY)uiExportDirectoryData)->VirtualAddress, uiDll);
    #ifdef DEBUG
    WCHAR pExportDir[] = { 'e', 'x', 'p', 'o', 'r', 't', 'd', 'i', 'r', ':', ' ', '%', 'p', '\n', 0 };
    ((WPRINTF)api->wprintf)(pExportDir, uiExportDirectory);
    #endif

    #ifdef DEBUG
    DWORD uiExportDirectorySize = ((PIMAGE_DATA_DIRECTORY)uiExportDirectoryData)->Size;
    WCHAR pExportDirSize[] = { 'e', 'x', 'p', 'o', 'r', 't', 's', 'i', 'z', 'e', ':', ' ', '%', 'd', '\n', 0 };
    ((WPRINTF)api->wprintf)(pExportDirSize, uiExportDirectorySize);
    #endif

    DWORD dwNumberOfEntries;
    UINT_PTR functionNameAddresses;
    UINT_PTR functionOrdinals;
    UINT_PTR functionAddresses;
    UINT_PTR rlOffset = 0;

    // get the number of exported functions
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
        // dereference the pointer in functionNameAddresses to get the current name string
        exportedFunctionName = (CHAR*)(uiDll + Rva2Offset(DEREF(functionNameAddresses), uiDll));
        // if exportedFunctionName != "ReflectiveLoader"
        if (my_strcmp(exportedFunctionName, (CHAR*)rlName) == 0)
        {
            #ifdef DEBUG
            CHAR error1[] = { 'R', 'L', ' ', 'N', 'o', 't', ' ', 'F', 'o', 'u', 'n', 'd', 0 };
            ((MESSAGEBOXA)api->MessageBoxA)(0, error1, error1, 0x0L);
            #endif

            // move to the next pointer to the next string
            functionNameAddresses += sizeof(DWORD); // 32 bit pointers
            // move to the next pointer to the next ordinal value
            functionOrdinals += sizeof(WORD);  // Ordinal values of 16 bit
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
            // address. It will be used as CreateThread's fourth parameter
            // (thread starting point) //
            functionAddresses += DEREF_16(functionOrdinals) * sizeof(DWORD);
            rlOffset = Rva2Offset(DEREF_32(functionAddresses), uiDll);
            break;
        }
    }

    if (rlOffset)
    { return rlOffset; }
    else
    { return 0; }
}


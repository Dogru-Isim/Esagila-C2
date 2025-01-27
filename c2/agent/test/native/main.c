#include "native.h"
#include <windows.h>
#include <winnt.h>

#define KERNEL32DLL_HASH 0x6A4ABC5B

FORCEINLINE DWORD ror13(DWORD d) { return _rotr(d, 13); }

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

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR cmdline, int nShowCmd)
{
    extern int printf (const char *__format, ...);
    //PPEB_LDR_DATA pPebLdrData = NtCurrentTeb()->ProcessEnvironmentBlock->Ldr;
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA pPebLdrData = (PPEB_LDR_DATA) ((UINT_PTR)pPeb->Ldr);
    //PPEB_LDR_DATA pPebLdrData = (PPEB_LDR_DATA) ((UINT_PTR)pPeb->Ldr - 16);

    PLIST_ENTRY pLdrDataTableEntry = (PLIST_ENTRY)(pPebLdrData->InLoadOrderModuleList).Flink;

    PWSTR dllName = NULL;
    USHORT usCounter = 0;
    DWORD ror13Hash = 0;
    UINT_PTR uiKernel32 = 0;

    dllName = (PWSTR)((PLDR_DATA_TABLE_ENTRY)pLdrDataTableEntry)->BaseDllName.Buffer;

    while (((PLDR_DATA_TABLE_ENTRY)pLdrDataTableEntry)->DllBase)
    {
        dllName = (PWSTR)((PLDR_DATA_TABLE_ENTRY)pLdrDataTableEntry)->BaseDllName.Buffer;
        usCounter = ((PLDR_DATA_TABLE_ENTRY)pLdrDataTableEntry)->BaseDllName.Length;

        if (stdStrCmpW(dllName, (WCHAR[]){ L'K', L'E', L'R', L'N', L'E', L'L', L'3', L'2', '.', L'D', L'L', L'L', 0}) == 0)
        {
            uiKernel32 = (UINT_PTR) ((PLDR_DATA_TABLE_ENTRY)pLdrDataTableEntry)->DllBase;
            printf("%S: %p\n", (WCHAR*)((PLDR_DATA_TABLE_ENTRY)pLdrDataTableEntry)->BaseDllName.Buffer, (LPVOID)uiKernel32);
            //MessageBoxA(0, "Lo", "Hey", 0x0L);
            break;
        }
        pLdrDataTableEntry = pLdrDataTableEntry->Flink;
    }


    PIMAGE_OPTIONAL_HEADER64 pImageOptionalHeader = &((PIMAGE_NT_HEADERS64)(uiKernel32 + ((PIMAGE_DOS_HEADER)uiKernel32)->e_lfanew))->OptionalHeader;
    PIMAGE_DATA_DIRECTORY pImageExportDataDirectory = &pImageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    printf("asdf: %p\n", (LPVOID)(pImageOptionalHeader));
    printf("asdf: %p\n", (LPVOID)(pImageExportDataDirectory));
    printf("asdf: %llu\n", ((UINT_PTR)pImageExportDataDirectory - (UINT_PTR)pImageOptionalHeader));

    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiKernel32 + pImageExportDataDirectory->VirtualAddress);

    printf("pImageExportDirectory: %p\n", (LPVOID)pImageExportDirectory);

    UINT_PTR uiOrdinalTable = uiKernel32 + pImageExportDirectory->AddressOfNameOrdinals;
    UINT_PTR uiNamePointerTable = uiKernel32 + pImageExportDirectory->AddressOfNames;
    UINT_PTR uiExportAddressTable = uiKernel32 + pImageExportDirectory->AddressOfFunctions;

    typedef HMODULE (WINBASEAPI WINAPI *LOAD_LIBRARY_A)(LPCSTR lpLibFileName);
    LOAD_LIBRARY_A loadLibraryA;

    for (DWORD n = 0; n < pImageExportDirectory->NumberOfNames; n++)
    {
        CCHAR* func = (LPSTR)( ((DWORD*)uiNamePointerTable)[n] + uiKernel32);
        WORD ordinal = ((WORD*)uiOrdinalTable)[n];
        UINT_PTR addRVA = ((WORD*)((UINT_PTR)uiKernel32 + pImageExportDirectory->AddressOfFunctions))[ordinal];
        printf("func: %s\n", func);
        if (stdStrCmpA(func, (CHAR[]){ 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0}) == 0)
        {
            printf("Found it!\n");
			loadLibraryA = (LOAD_LIBRARY_A)(uiKernel32 + addRVA);
			break;
			//return ((UINT_PTR)uiKernel32 + addRVA);
		}
    }

    /*
    DWORD n = pImageExportDirectory->NumberOfNames;
    while (n--)
    {
        printf("func: %s\n", (CHAR*)(uiKernel32 + *(DWORD*)uiNamePointerTable));
        if (stdStrCmpA((CHAR*)uiKernel32 + *(DWORD*)uiNamePointerTable, (CHAR[]){ 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0}) == 0)
        {
            printf("Found it!");
            loadLibraryA = (LOAD_LIBRARY_A)(uiKernel32 + uiExportAddressTable + uiOrdinalTable);
            break;
        }
        uiNamePointerTable += sizeof(DWORD);
        uiOrdinalTable += sizeof(DWORD);
    }
    */

    loadLibraryA("msvcrt.dll");

    return 0;
}



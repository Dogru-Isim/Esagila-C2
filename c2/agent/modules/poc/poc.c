#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdbool.h>
#include "addresshunter.h"

typedef int(WINAPI *MESSAGEBOXA)(HWND, LPCTSTR, LPCTSTR, UINT32);
typedef HMODULE(WINAPI *LOADLIBRARYA)(LPCSTR lpLibFileName);

// we declare some common stuff in here...
#define DLL_QUERY_HMODULE		6

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

typedef ULONG_PTR (WINAPI * REFLECTIVELOADER)( VOID );
typedef bool (WINAPI * DLLMAIN)( HINSTANCE, DWORD, LPVOID );

#define DLLEXPORT  __declspec( dllexport ) 

typedef struct API_ {
    UINT64 loadLibraryFn;
    UINT64 messageBoxAFn;
} API, *PAPI;

DLLEXPORT DWORD WINAPI ReflectiveLoader()
{
    API Api = { 0 };
    PAPI api = &Api;

    UINT64 kernel32dll;
    UINT64 user32dll;

    CHAR user32_c[] = { 'u', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l', 0 };

    CHAR loadLibrary_c[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0 };
    CHAR messageBoxA_c[] = { 'M', 'e', 's', 's', 'a', 'g', 'e', 'B', 'o', 'x', 'A', 0 };

    kernel32dll = GetKernel32();
    api->loadLibraryFn = (UINT64)(GetSymbolAddress((HANDLE)kernel32dll, loadLibrary_c));

    user32dll = (UINT64)(((LOADLIBRARYA)(api->loadLibraryFn))(user32_c));

    api->messageBoxAFn = GetSymbolAddress((HANDLE)user32dll, messageBoxA_c);

    CHAR a[] = { 'H', 'i', 0 };
    CHAR b[] = { 'R', 'l', 'L', 'o', 'a', 'd', 'e', 'r', 0 };
    ((MESSAGEBOXA)(api->messageBoxAFn))(0, a, b, 0x0000000L);

    return 0x6969;
}

BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
    DWORD hi = ReflectiveLoader();
    BOOL bReturnValue = TRUE;
	  switch( dwReason ) 
        { 
		    case DLL_PROCESS_ATTACH:
			      MessageBoxA( NULL, "Hello from DllMain!", "Reflective Dll Injection", MB_OK );
            printf("%d", hi);
			      break;
		    case DLL_PROCESS_DETACH:
		    case DLL_THREAD_ATTACH:
		    case DLL_THREAD_DETACH:
		        break;
        }
	  return bReturnValue;
}

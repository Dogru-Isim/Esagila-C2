#ifndef TYPEDEFS_H
#define TYPEDEFS_H

#include <windows.h>

typedef int                 BOOL;

#ifndef FALSE
#define FALSE               0
#endif

#ifndef TRUE
#define TRUE                1
#endif

#define DEREF(name) *(UINT_PTR *)(name)
#define DEREF_64(name) *(DWORD64 *)(name)
#define DEREF_32(name) *(DWORD *)(name)
#define DEREF_16(name) *(WORD *)(name)
#define DEREF_8(name) *(BYTE *)(name)

#ifdef DEBUG
    #define DEBUG_PRINTF_WARNING(fmt, ...) ((PRINTF)agent->api.printf)("[WARNING] " fmt, __VA_ARGS__)
    #define DEBUG_PRINTF_ERROR(fmt, ...) ((PRINTF)agent->api.printf)("[ERROR] " fmt, __VA_ARGS__)
#else
    #define DEBUG_PRINTF_WARNING(fmt, ...) ((void)0) // No operation, remove the string literal from the binary
    #define DEBUG_PRINTF_ERROR(fmt, ...) ((void)0) // No operation, remove the string literal from the binary
#endif

// redefine UNICODE_STR struct
typedef struct _UNICODE_STR {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR pBuffer;
} UNICODE_STR, *PUNICODE_STR;

// redefine PEB_LDR_DATA struct
typedef struct _PEB_LDR_DATA {
    DWORD dwLength;
    DWORD dwInitialized;
    LPVOID lpSsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    LPVOID lpEntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

// redefine LDR_DATA_TABLE_ENTRY struct
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
    ULONG Flags;
    SHORT LoadCount;
    SHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

// redefine PEB_FREE_BLOCK struct
typedef struct _PEB_FREE_BLOCK
{
    struct _PEB_FREE_BLOCK *pNext;
    DWORD dwSize;
} PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;

// redefine PEB struct
typedef struct __PEB
{
    BYTE bInheritedAddressSpace;
    BYTE bReadImageFileExecOptions;
    BYTE bBeingDebugged;
    BYTE bSpareBool;
    LPVOID lpMutant;
    LPVOID lpImageBaseAddress;
    PPEB_LDR_DATA pLdr;
    LPVOID lpProcessParameters;
    LPVOID lpSubSystemData;
    LPVOID lpProcessHeap;
    PRTL_CRITICAL_SECTION pFastPebLock;
    LPVOID lpFastPebLockRoutine;
    LPVOID lpFastPebUnlockRoutine;
    DWORD dwEnvironmentUpdateCount;
    LPVOID lpKernelCallbackTable;
    DWORD dwSystemReserved;
    DWORD dwAtlThunkSListPtr32;
    PPEB_FREE_BLOCK pFreeList;
    DWORD dwTlsExpansionCounter;
    LPVOID lpTlsBitmap;
    DWORD dwTlsBitmapBits[2];
    LPVOID lpReadOnlySharedMemoryBase;
    LPVOID lpReadOnlySharedMemoryHeap;
    LPVOID lpReadOnlyStaticServerData;
    LPVOID lpAnsiCodePageData;
    LPVOID lpOemCodePageData;
    LPVOID lpUnicodeCaseTableData;
    DWORD dwNumberOfProcessors;
    DWORD dwNtGlobalFlag;
    LARGE_INTEGER liCriticalSectionTimeout;
    DWORD dwHeapSegmentReserve;
    DWORD dwHeapSegmentCommit;
    DWORD dwHeapDeCommitTotalFreeThreshold;
    DWORD dwHeapDeCommitFreeBlockThreshold;
    DWORD dwNumberOfHeaps;
    DWORD dwMaximumNumberOfHeaps;
    LPVOID lpProcessHeaps;
    LPVOID lpGdiSharedHandleTable;
    LPVOID lpProcessStarterHelper;
    DWORD dwGdiDCAttributeList;
    LPVOID lpLoaderLock;
    DWORD dwOSMajorVersion;
    DWORD dwOSMinorVersion;
    WORD wOSBuildNumber;
    WORD wOSCSDVersion;
    DWORD dwOSPlatformId;
    DWORD dwImageSubsystem;
    DWORD dwImageSubsystemMajorVersion;
    DWORD dwImageSubsystemMinorVersion;
    DWORD dwImageProcessAffinityMask;
    DWORD dwGdiHandleBuffer[34];
    LPVOID lpPostProcessInitRoutine;
    LPVOID lpTlsExpansionBitmap;
    DWORD dwTlsExpansionBitmapBits[32];
    DWORD dwSessionId;
    ULARGE_INTEGER liAppCompatFlags;
    ULARGE_INTEGER liAppCompatFlagsUser;
    LPVOID lppShimData;
    LPVOID lpAppCompatInfo;
    UNICODE_STR usCSDVersion;
    LPVOID lpActivationContextData;
    LPVOID lpProcessAssemblyStorageMap;
    LPVOID lpSystemDefaultActivationContextData;
    LPVOID lpSystemAssemblyStorageMap;
    DWORD dwMinimumStackCommit;
} _PEB, *_PPEB;



typedef ULONG_PTR (WINAPI *REFLECTIVELOADER)();
typedef BOOL (WINAPI *DLLMAIN)(HINSTANCE, DWORD, LPVOID);

// kernel32.dll exports
typedef HMODULE(WINAPI *LOADLIBRARYA)(LPCSTR lpLibFileName);
typedef BOOL(WINAPI *CLOSEHANDLE)(HANDLE);
typedef HANDLE(WINAPI *GETCURRENTPROCESS)();
typedef DWORD(WINAPI *GETLASTERROR)();
typedef LPVOID(WINAPI *VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef HANDLE(WINAPI *CREATETHREAD)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI *VIRTUALPROTECT)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef DWORD(WINAPI *WAITFORSINGLEOBJECT)(HANDLE hHandle, DWORD dwMilliseconds);
typedef VOID(WINAPI *SLEEP)(DWORD dwMilliseconds);

// advapi32.dll exports
typedef BOOL(WINAPI *OPENPROCESSTOKEN)(HANDLE, DWORD, PHANDLE);
typedef BOOL(WINAPI *GETTOKENINFORMATION)(HANDLE, TOKEN_INFORMATION_CLASS,
                                          LPVOID, DWORD, PDWORD);
typedef BOOL(WINAPI *LOOKUPPRIVILEGENAMEW)(LPCWSTR, PLUID, LPWSTR, LPDWORD);

// msvcrt.dll exports
typedef int(WINAPI *WPRINTF)(wchar_t *format, ...);
typedef int(WINAPI *PRINTF)(char *format, ...);
typedef void *(WINAPI *CALLOC)(size_t num, size_t size);
typedef void(WINAPI *FREE)(PVOID memblock);
typedef void *(WINAPI *MALLOC)(size_t);
typedef int(WINAPI *SNPRINTF)(CHAR* str, DWORD size, PCSTR format, ...);

// user32.dll export
typedef int(WINAPI *MESSAGEBOXW)(HWND, LPWSTR, LPWSTR, UINT32);
typedef int(WINAPI *MESSAGEBOXA)(HWND, LPCTSTR, LPCTSTR, UINT32);

// crypt32.dll export
typedef BOOL(WINAPI *CRYPTSTRINGTOBINARYA)(LPCSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*);
typedef BOOL(WINAPI *CRYPTBINARYTOSTRINGA)(const BYTE*, DWORD, DWORD, LPSTR, DWORD*);

typedef void* HINTERNET;
typedef UINT64 INTERNET_PORT;

// WinHTTP exports
typedef HINTERNET(WINAPI *WINHTTPOPEN)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET(WINAPI *WINHTTPCONNECT)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
typedef HINTERNET(WINAPI *WINHTTPOPENREQUEST)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, DWORD);
typedef BOOL(WINAPI *WINHTTPSENDREQUEST)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL(WINAPI *WINHTTPREADDATA)(HINTERNET, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI *WINHTTPRECEIVERESPONSE)(HINTERNET, LPVOID);
typedef BOOL(WINAPI *WINHTTPQUERYDATAAVAILABLE)(HINTERNET, LPDWORD);
typedef BOOL(WINAPI *WINHTTPQUERYHEADERS)(HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);
typedef BOOL(WINAPI *WINHTTPCLOSEHANDLE)(HINTERNET);

// shlwapi.dll (StrToIntW)
typedef DWORD(WINAPI *STRTOINTW)(PCWSTR);

// processthreadsapi
typedef VOID(WINAPI *EXITTHREAD)(DWORD dwExitCode);

// standard esagila api
typedef CHAR*(WINAPI *RUNCMD)(CCHAR* cmd, PDWORD size);
typedef CHAR*(WINAPI *WHOAMI)(DWORD* pdwSizeOfOutput);
typedef BOOL(WINAPI *INJECTINTOPROCESS)(PBYTE shellcode, SIZE_T dwShellcodeSize, LPCSTR lpApplicationName);

typedef struct API_
{
    UINT64 LoadLibraryA;
    UINT64 CloseHandle;
    UINT64 Sleep;
    UINT64 WinHttpCloseHandle;
    UINT64 WinHttpConnect;
    UINT64 WinHttpOpen;
    UINT64 WinHttpOpenRequest;
    UINT64 WinHttpSendRequest;
    UINT64 WinHttpReceiveResponse;
    UINT64 WinHttpQueryDataAvailable;
    UINT64 WinHttpQueryHeaders;
    UINT64 WinHttpReadData;
    UINT64 malloc;
    UINT64 calloc;
    UINT64 free;
    UINT64 VirtualProtect;
    UINT64 VirtualAlloc;
    UINT64 CreateThread;
    UINT64 WaitForSingleObject;
    UINT64 GetLastError;
    UINT64 MessageBoxA;
    UINT64 MessageBoxW;
    UINT64 wprintf;
    UINT64 printf;
    UINT64 CryptStringToBinaryA;
    UINT64 CryptBinaryToStringA;
    UINT64 StrToIntW;
    UINT64 snprintf;
    UINT64 ExitThread;
} API, *PAPI;

typedef struct ESG_STD_API_
{
    UINT64 RunCmd;
    UINT64 Whoami;
    UINT64 injectIntoProcess;
} ESG_STD_API, *PESG_STD_API;

typedef struct DLL_
{
    LPVOID pBuffer;
    DWORD Size;
} DLL, * PDLL;

#endif  // TYPEDEF_H

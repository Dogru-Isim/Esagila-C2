#ifndef HTTP_H
#define HTTP_H

#include "std.h"

#define WINHTTP_NO_ADDITIONAL_HEADERS NULL
#define WINHTTP_NO_REQUEST_DATA NULL
#define WINHTTP_QUERY_CONTENT_LENGTH 5
#define WINHTTP_HEADER_NAME_BY_INDEX NULL
#define WINHTTP_NO_HEADER_INDEX NULL

/*
This function sends a get request to a web server

Input:
    [in] PAPI api: a pointer to the API structure
    [in] WCHAR* wcServer: host name or an IP address of an HTTP server
    [in] INTERNET_PORT port: port number
    [in] WCHAR* wcPath: path to query
Output:
    Success -> CHAR*: web server response, needs to be freed
    Failure -> NULL
*/
CHAR* GetRequest(PAPI api, WCHAR* wcServer, INTERNET_PORT port, WCHAR* wcPath);

/*
This function sends a post request to an endpoint

Input:
    [in] PAPI api: a pointer to the API struct
    [in] WCHAR* server: a hostname or an IP address
    [in] INTERNET_PORT port: a port number
    [in] const WCHAR endpoint: a path on the server
    [in] CCHAR* data: a json data
Output:
    The function returns nothing
*/
void PostRequest(PAPI api, WCHAR* server, INTERNET_PORT port, const WCHAR* endpoint, CHAR* data);

//
/*
the return need to be freed

Note:
    TODO: combine this function with GetRequest
*/
LPVOID httpGetExecutable(PAPI api, PDWORD pdwDllSize, WCHAR* wEndpoint, WCHAR* wcServer, INTERNET_PORT dwPort);

#endif  // HTTP_H

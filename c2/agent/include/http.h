#ifndef HTTP_H
#define HTTP_H

#include "std.h"

#define WINHTTP_NO_ADDITIONAL_HEADERS NULL
#define WINHTTP_NO_REQUEST_DATA NULL
#define WINHTTP_QUERY_CONTENT_LENGTH 5
#define WINHTTP_HEADER_NAME_BY_INDEX NULL
#define WINHTTP_NO_HEADER_INDEX NULL

CHAR* GetRequest(PAPI api, WCHAR* wcServer, INTERNET_PORT port, WCHAR* wcPath);

void PostRequest(PAPI api, WCHAR* server, INTERNET_PORT port, const WCHAR* endpoint, CHAR* data);

LPVOID winHTTPClient(PAPI api, PDWORD pdwDllSize);

#endif  // HTTP_H

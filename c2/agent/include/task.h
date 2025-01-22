#ifndef TASK_H
#define TASK_H

#include <windows.h>

typedef struct Task_
{
    CHAR* taskId;
    CHAR* taskParams;
    CHAR* taskType;
    CHAR* agentUuid;
} Task, *PTask;

#define TASK_CMD (CHAR[]){ 'c', 'm', 'd', 0 };
#define TASK_WHOAMI (CHAR[]){ 'w', 'h', 'o', 'a', 'm', 'i', 0 };
#define TASK_SHUTDOWN (CHAR[]){ 's', 'h', 'u', 't', 'd', 'o', 'w', 'n', 0 };
#define TASK_EXECUTE_ASSEMBLY (CHAR[]){ 'e', 'x', 'e', 'c', 'u', 't', 'e', '_', 'a', 's', 's', 'e', 'm', 'b', 'l', 'y', 0 };

#endif // TASK_H

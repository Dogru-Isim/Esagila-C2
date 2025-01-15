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

#endif // TASK_H

#ifndef JSON_H
#define JSON_H

#include <windows.h>
#include "typedefs.h"
#include "task.h"

/*
This function reads and parses a task in json format

Input:
    [in] PAPI api: a pointer to the API struct

    [in] CHAR* json: a pointer to a json string

    [out] [heap] CHAR** taskId: a pointer to receive the taskId member in json that needs to be freed

    [out] [heap] CHAR** taskType: a pointer to receive the taskType member in json that needs to be freed

    [out] [heap] CHAR** uuid: a pointer to receive the uuid member in json that needs to be freed

Output:
    Success -> CHAR*: a pointer to a base64 encoded string that holds the task value that `needs to be freed`

    Json doesn't hold any data -> NULL

Note:
    If the `task` member of json is empty (a.k.a. what to run is determined only by `taskType`) the return value is empty string that still `needs to be freed`
*/
Task readJsonTask(PAPI api, CHAR* json);


#endif

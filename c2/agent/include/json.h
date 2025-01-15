#ifndef JSON_H
#define JSON_H

#include <windows.h>
#include "typedefs.h"

extern PAPI api;

typedef struct Task_
{
    CHAR* taskId;
    CHAR* taskParams;
    CHAR* taskType;
    CHAR* agentUuid;
} Task, *PTask;

/*
This struct contains a series of null terminated strings called tokens
This struct represents a tokenized string

Members:
    CHAR* tokenizedString: contains a series of null terminated strings called tokens
    DWORD numberOfTokens: the amount of tokens that can be used to loop through the tokens
Example:
    First\0Second\0Third\0Token
Note:
*/
typedef struct Tokens
{
    CHAR* tokenizedString;
    DWORD numberOfTokens;
} Tokens, *PTokens;

/*
This function tokenizes a string

Input:
    [in] PAPI api: an instance of the API struct

    [in] CCHAR* str: the string to tokenize

    [in] CCHAR delim: a delimiter to use for tokenization

Output:
    A `Tokens` struct whose member `tokenizedString` needs to be freed

Note:
    The tokens can be retrieved using the getToken function

    // TODO: the final numberOfTokens value is not accurate if the last char 
    // or `delim` is not a null byte or if there are consecutive delimiters
*/
Tokens myStrtok(CCHAR* str, CCHAR delim);

/*
This function retrieves a token in a Tokens struct

Input:
    [in] PAPI api: an instance to the API struct

    [in] Tokens tokenizedStr: a `Tokens` struct obtained from myStrtok

    [in] DWORD index: the index of the requested token

Output:
    Success -> CHAR*: a pointer to the requested token

    Failure -> NULL

Note:
    the `tokenizedString` member of `tokens` must not have been freed before running the function
*/
CHAR* getToken(Tokens tokens, DWORD index);

/*
This function recursively removes a character from the start of a string

Input:
    [in] PAPI api: an API struct

    [in] CCHAR* str: string 

    [in] CHAR trim: character to trim

Output:
    A CHAR* that needs to be freed

Note:
    If `str` only consists of `trim` characters, an empty string that still `needs to be freed` is returned
*/
CHAR* myStartTrim(CCHAR* str, CHAR trim);

/*
This function recursively removes a character from the end of a string

Input:
    [in] PAPI api: a pointer to the API struct

    [in] CCHAR* str: string

    [in] CHAR trim: character to remove

Output:
    Success -> a CHAR* that needs to be freed

    Failure -> `str` is empty -> null terminated empty string

    Failure -> memory allocation failed -> NULL

Note:
    If `str` only consists of trim characters a pointer to an empty string that still needs to be freed is returned
*/
CHAR* myEndTrim(CCHAR* str, CHAR trim);

/*
This function recursively removes a character from both sides of a string

Input:
    [in] PAPI api: a pointer to the API struct

    [in] CHAR* str: the string to trim

    [in] CHAR trim: the character to remove

Output:
    heap CHAR*: the trimmed string that needs to be freed

Note:
    if `str` only consists of the `trim` character, an empty string that still `needs to be freed` is returned is returned
*/
CHAR* myTrim(CCHAR* str, CHAR trim);

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
Task parseJsonTask(CHAR* json);

#endif // JSON_H

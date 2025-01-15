#ifndef TOKENIZER_H
#define TOKENIZER_H

#include <windows.h>
#include "typedefs.h"

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
Tokens myStrtok(PAPI api, CCHAR* str, CCHAR delim);

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
CHAR* getToken(PAPI api, Tokens tokens, DWORD index);

#endif  // TOKENIZER_H

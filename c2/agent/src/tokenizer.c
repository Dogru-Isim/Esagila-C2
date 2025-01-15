#include "../include/tokenizer.h"
#include "../include/std.h"

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
Tokens myStrtok(PAPI api, CCHAR* str, CCHAR delim)
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
    [in] PAPI api: an instance to the API struct

    [in] Tokens tokenizedStr: a `Tokens` struct obtained from myStrtok

    [in] DWORD index: the index of the requested token

Output:
    Success -> CHAR*: a pointer to the requested token

    Failure -> NULL

Note:
    the `tokenizedString` member of `tokens` must not have been freed before running the function
*/
CHAR* getToken(PAPI api, Tokens tokens, DWORD index)
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

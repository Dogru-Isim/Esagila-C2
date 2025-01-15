#include "../include/std.h"

// NOTE: These functions are defined mostly to be used
// before the dynamic linking of DLLs

/*
 * This function is used to compare two null terminated strings
 *
 * Input:
 *      [in] const char *p1: first string
 *
 *      [in] const char *p1: second string
 *
 * Output:
 *      0 -> strings are the same
 *
 *      Non-zero value -> strings are different
 */
int my_strcmp(const char *p1, const char *p2)
{
    const unsigned char *s1 = (const unsigned char *)p1;
    const unsigned char *s2 = (const unsigned char *)p2;
    unsigned char c1, c2;
    do
    {
        c1 = (unsigned char)*s1++;
        c2 = (unsigned char)*s2++;
        if (c1 == '\0')
        { return c1 - c2; }
    }
    while (c1 == c2);
    return c1 - c2;
}

/*
 * This function calculates the size for a base64 decoded value
 *
 * Input:
 *      [in] size_t len: the size of the base64 encoded value
 *
 * Output:
 *      size_t -> size of the base64 decoded value
 */
size_t base64_raw_size(size_t len)
{
    size_t padding = 0;

    // Determine padding based on the length of the Base64 string
    if (len > 0)
    {
        padding = (len % 4 == 0) ? 0 : (4 - (len % 4));
    }

    // Calculate the raw size
    return (len * 3) / 4 - padding;
}

/*
 * This function copies a region in memory onto another
 * 
 * Input:
 *      void* dest: start of the memory region to copy data onto
 *
 *      const void* src: start of the memory region to copy data from
 *
 *      size_t len: how many bytes to copy
 *
 * Output:
 *      void*: a pointer to `dest`
 *
 * Note:
 *      NOTE: I believe the return is redundant. A success value would be more appropriate
 */
void* myMemcpy (void* dest, const void* src, size_t len)
{
  char* d = dest;
  const char* s = src;
  while (len--)
    *d++ = *s++;
  return dest;
}

/*
 * This function set a `len` amount of bytes to `val` starting from `dest`
 *
 * Input:
 *      [in] void* dest: a pointer to the start of the memory region
 *
 *      [in] int val: value to write
 *
 *      [in] size_t len: amount of `val`s to write
 *
 * Output:
 *      void*: a pointer tot `dest`
 *
 * Note:
 *      NOTE: I believe the return is redundant. A success value would be more appropriate
 */
void* memset(void* dest, int val, size_t len)
{
    unsigned char* ptr = dest;
    while (len-- > 0)
        *ptr++ = val;
    return dest;
}

/*
 * This function calculates the size of a CHAR excluding the null byte
 *
 * Input:
 *      [in] const CHAR* s1: string to calculate its size
 *
 * Output:
 *      int: size of the string excluding the null byte
 */
int myStrlenA(const CHAR* s1)
{
    const CHAR *s2 = s1; // Pointer to traverse the string

    while (*s2)
    { s2++; }
    return s2 - s1;
}

/*
 * This function calculates the size of a WCHAR excluding the null byte
 *
 * Input:
 *      [in] const CHAR* s1: string to calculate its size
 *
 * Output:
 *      int: size of the string excluding the null byte
 */
int myStrlenW(const WCHAR* s1)
{
    const WCHAR *s2 = s1; // Pointer to traverse the wide string

    while (*s2)
    { s2++; }
    return s2 - s1;
}

/*
 * This function copies a region in memory onto another using WCHARs
 * 
 * Input:
 *      [in] void* dest: start of the memory region to copy data onto
 *
 *      [in] const void* src: start of the memory region to copy data from
 *
 *      [in] size_t len: how many WCHARs to copy
 */
void myMemcpyW (void *dest, const void *src, size_t len)
{
  wchar_t *d = dest;
  const wchar_t *s = src;
  while (len--)
    *d++ = *s++;
}

/*
 * This function is deprecated and should not be used before making changes
 */
wchar_t* myConcatW(PAPI api, const wchar_t *s1, const wchar_t *s2)
{
    const size_t len1 = myStrlenW(s1);
    const size_t len2 = myStrlenW(s2);
    wchar_t* result = (wchar_t*)((MALLOC)api->malloc)(len1 + len2 + 1); // +1 for the null-terminator
    myMemcpyW(result, s1, len1);
    myMemcpyW(result + len1, s2, len2 + 1); // +1 to copy the null-terminator
    return result;
}

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

VOID myStartTrim(CCHAR* str, CHAR trimmedStr[], CHAR trim)
{
    DWORD dwSizeOriginalStr;
    // find the index of the last trim function
    DWORD dwLastTrim = 0;

    while (str[dwLastTrim] == trim)
    {
        dwLastTrim++;
    }

    memcpy(trimmedStr, str+dwLastTrim, dwSizeOriginalStr-dwLastTrim);
}

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
CHAR* myEndTrim(PAPI api, CCHAR* str, CHAR trim)
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
    [in] PAPI api: a pointer to the API struct

    [in] CHAR* str: the string to trim

    [in] CHAR trim: the character to remove

Output:
    heap CHAR*: the trimmed string that needs to be freed

Note:
    if `str` only consists of the `trim` character, an empty string that still `needs to be freed` is returned is returned
*/
CHAR* myTrim(PAPI api, CCHAR* str, CHAR trim)
{
    CHAR* startTrimmedStr = myStartTrim(api, str, trim);
    CHAR* outStr = myEndTrim(api, startTrimmedStr, trim);
    ((FREE)api->free)(startTrimmedStr);
    return outStr;
}


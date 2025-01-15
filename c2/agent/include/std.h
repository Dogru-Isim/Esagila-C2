#ifndef STD_H
#define STD_H

#include <windows.h>
#include <inttypes.h>
#include "typedefs.h"

// NOTE: These functions are defined mostly to be used before
// the dynamic linking off DLLs


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
int my_strcmp(const char *p1, const char *p2);


/*
 * This function calculates the size for a base64 decoded value
 *
 * Input:
 *      [in] size_t len: the size of the base64 encoded value
 *
 * Output:
 *      size_t -> size of the base64 decoded value
 */
size_t base64_raw_size(size_t len);


/*
 * This function copies a region in memory onto another
 * 
 * Input:
 *      [in] void* dest: start of the memory region to copy data onto
 *
 *      [in] const void* src: start of the memory region to copy data from
 *
 *      [in] size_t len: how many bytes to copy
 *
 * Output:
 *      void*: a pointer to `dest`
 *
 * Note:
 *      NOTE: I believe the return is redundant. A success value would be more appropriate
 */
void * myMemcpy (void *dest, const void *src, size_t len);


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
void* memset(void* dest, int val, size_t len);


/*
 * This function calculates the size of a CHAR excluding the null byte
 *
 * Input:
 *      [in] const CHAR* s1: string to calculate its size
 *
 * Output:
 *      int: size of the string excluding the null byte
 */
int myStrlenA(const CHAR* s1);


/*
 * This function calculates the size of a WCHAR excluding the null byte
 *
 * Input:
 *      [in] const CHAR* s1: string to calculate its size
 *
 * Output:
 *      int: size of the string excluding the null byte
 */
int myStrlenW(const WCHAR* s1);


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
void myMemcpyW (void *dest, const void *src, size_t len);

/*
 * This function is deprecated and should not be used before making changes
 */
wchar_t* myConcatW(PAPI api, const wchar_t *s1, const wchar_t *s2);


/*
This function recursively removes a character from the start of a string

Input:
    [in] CCHAR* str: original string

    [out] CHAR[] trimmedStr: an array to receive the new string, its size should be as big as the length of the original string including the null byte

    [in] CHAR trim: character to trim

Output:
    The function returns nothing, newly trimmed string is written to trimmedStr[]
*/
VOID myStartTrim(CCHAR* str, CHAR trimmedStr[], CHAR trim);


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
CHAR* myEndTrim(PAPI api, CCHAR* str, CHAR trim);


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
CHAR* myTrim(PAPI api, CCHAR* str, CHAR trim);


#endif  // STD_H

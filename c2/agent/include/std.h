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
 *      const char *p1: first string
 *
 *      const char *p1: second string
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
 *      size_t len: the size of the base64 encoded value
 *
 * Output:
 *      size_t -> size of the base64 decoded value
 */
size_t base64_raw_size(size_t len);

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
void * myMemcpy (void *dest, const void *src, size_t len);

/*
 * This function set a `len` amount of bytes to `val` starting from `dest`
 *
 * Input:
 *      void* dest: a pointer to the start of the memory region
 *
 *      int val: value to write
 *
 *      size_t len: amount of `val`s to write
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
 *      const CHAR* s1: string to calculate its size
 *
 * Output:
 *      int: size of the string excluding the null byte
 */
int myStrlenA(const CHAR* s1);

/*
 * This function calculates the size of a WCHAR excluding the null byte
 *
 * Input:
 *      const CHAR* s1: string to calculate its size
 *
 * Output:
 *      int: size of the string excluding the null byte
 */
int myStrlenW(const WCHAR* s1);

/*
 * This function copies a region in memory onto another using WCHARs
 * 
 * Input:
 *      void* dest: start of the memory region to copy data onto
 *
 *      const void* src: start of the memory region to copy data from
 *
 *      size_t len: how many WCHARs to copy
 */
void myMemcpyW (void *dest, const void *src, size_t len);

/*
 * This function is deprecated and should not be used before making changes
 */
wchar_t* myConcatW(PAPI api, const wchar_t *s1, const wchar_t *s2);

#endif  // STD_H

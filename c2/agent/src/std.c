#include "../include/std.h"

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
 *      size_t len: the size of the base64 encoded value
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
 *      const CHAR* s1: string to calculate its size
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
 *      const CHAR* s1: string to calculate its size
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

void myMemcpyW (void *dest, const void *src, size_t len)
{
  wchar_t *d = dest;
  const wchar_t *s = src;
  while (len--)
    *d++ = *s++;
}

wchar_t* myConcatW(PAPI api, const wchar_t *s1, const wchar_t *s2)
{
    const size_t len1 = myStrlenW(s1);
    const size_t len2 = myStrlenW(s2);
    wchar_t* result = (wchar_t*)((MALLOC)api->malloc)(len1 + len2 + 1); // +1 for the null-terminator
    myMemcpyW(result, s1, len1);
    myMemcpyW(result + len1, s2, len2 + 1); // +1 to copy the null-terminator
    return result;
}


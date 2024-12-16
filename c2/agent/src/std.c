#include "../include/std.h"

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

void * myMemcpy (void *dest, const void *src, size_t len)
{
  char *d = dest;
  const char *s = src;
  while (len--)
    *d++ = *s++;
  return dest;
}

void* memset(void* dest, int val, size_t len)
{
    unsigned char* ptr = dest;
    while (len-- > 0)
        *ptr++ = val;
    return dest;
}

int myStrlenA(const CHAR* s1)
{
    const CHAR *s2 = s1; // Pointer to traverse the string

    while (*s2)
    { s2++; }
    return s2 - s1;
}

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

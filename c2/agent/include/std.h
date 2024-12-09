#ifndef STD_H
#define STD_H

#include <windows.h>
#include <inttypes.h>
#include "typedefs.h"

// custom strcmp function since this function will be called by GetSymbolAddress
// which means we have to call strcmp before loading msvcrt.dll
// so we are writing our own my_strcmp so that we don't have to play with egg or
// chicken dilemma
int my_strcmp(const char *p1, const char *p2);

size_t base64_raw_size(size_t len);

void * myMemcpy (void *dest, const void *src, size_t len);

void* memset(void* dest, int val, size_t len);

int myStrlenA(const CHAR* s1);

int myStrlenW(const WCHAR* s1);

void myMemcpyW (void *dest, const void *src, size_t len);

wchar_t* myConcatW(PAPI api, const wchar_t *s1, const wchar_t *s2);

#endif  // STD_H

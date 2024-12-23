#ifndef EXEC_H
#define EXEC_H
#ifndef DLLEXPORT
#define DLLEXPORT __declspec(dllexport)
#endif

#include <windows.h>

DLLEXPORT VOID WINAPI injectIntoProcess(BYTE*, SIZE_T, LPCSTR);

#endif  // EXEC_H

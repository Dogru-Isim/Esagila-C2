#ifndef EXEC_H
#define EXEC_H

#include <windows.h>

VOID injectIntoProcess(BYTE shellcode[], SIZE_T dwShellcodeSize, LPCSTR lpApplicationName);

#endif  // EXEC_H

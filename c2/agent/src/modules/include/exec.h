#ifndef EXEC_H
#define EXEC_H

#include <windows.h>

VOID injectIntoProcess(BYTE shellcode[], LPCSTR lpApplicationName);

#endif  // EXEC_H

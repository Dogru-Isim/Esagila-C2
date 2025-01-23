#ifndef EXEC_H
#define EXEC_H

#include <stdio.h>
#include <windows.h>

#ifndef DLLEXPORT
#define DLLEXPORT __declspec(dllexport)
#endif

#define WIN32_LEAN_AND_MEAN

typedef int BOOL;

/*
 * This function creates a process, injects shellcode into that process, and runs that shellcode
 *
 * Input:
 *      [in] BYTE[] shellcode: shellcode to inject and execute
 *
 *      [in] SIZE_T dwShellcodeSize: size of the shellcode array
 *
 *      [in] LPCSTR lpApplicationName: name of the application to create a process of
 *
 * Output:
 *      BOOL: If function fails FALSE, otherwise TRUE
 *
 * Note:
 *      The function uses a standard CreateProcessA, VirtualAllocEx,
 *      WriteProcessMemory, and CreateRemoteThread execution flow. 
 *      The memory is allocated with PAGE_EXECUTE_READWRITE protections and it doesn't revert the protection rights
 */
DLLEXPORT BOOL WINAPI injectIntoProcess(BYTE*, SIZE_T, LPCSTR);

#endif  // EXEC_H

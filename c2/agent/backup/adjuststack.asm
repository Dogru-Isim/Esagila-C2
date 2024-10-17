extern getprivs
global adjuststack

segment .text

adjuststack:
    push rdi              ; store old rdi value in stack
    mov rdi, rsp          ; store old rsp value in rdi
    and rsp, byte -0x10   ; allign the stack pointer to be a multiple 16 bytes (x86_64)
    sub rsp, byte +0x20   ; allocate "shadow space" for the extern `getprivs` function
    call getprivs         ; call extern function
    mov rsp, rdi          ; restore old rsp value
    pop rdi               ; restore old rdi value
    ret

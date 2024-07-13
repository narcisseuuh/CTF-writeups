global _start 

section .text 

_start:
    xor rax, rax
    mov al, 0x0
    mov rdi, 0x602300
    mov rsi, 0x602190
    mov rdx, 0x20 
    syscall 

    xor rax, rax 
    mov al, 0x1
    mov rdi, 0x1 ; stdout
    mov rsi, 0x602190
    syscall 

    mov al, 0x3c 
    mov rdi, 0
    syscall

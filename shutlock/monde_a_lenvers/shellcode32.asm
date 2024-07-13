global _start

section .text

_start:
    mov esp, 0x602050
    xor eax, eax
    mov ecx, 0
    mov edx, 0777

    ;flag.txt
    
    push 0x7478742e
    push 0x67616c66
    lea ebx, [esp]


    push edx
    push ecx
    push ebx

    mov al, 0x5
    int 0x80
    
    mov ecx, 0x602300
    mov [ecx], eax

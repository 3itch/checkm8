.globl call_sinit
call_sinit:
    mov eax, 8
    mov ebx, mpb_base
    getsec
    ret
.686P
.XMM
.MODEL FLAT, C
OPTION CASEMAP:NONE
.code

InvokeIntegerArguments PROC
    push ebp
    mov ebp, esp
    push ebx
    push esi
    mov ebx, [ebp + 8]
    mov esi, [ebp + 20]
    mov ecx, [ebp + 24]

    ; The untouched variadic tail contains native DWORD slots.
    test ecx, ecx
    jz prefix
tail:
    dec ecx
    push DWORD PTR [esi + ecx * 4]
    jnz tail
prefix:
    mov esi, [ebp + 12]
    mov ecx, [ebp + 16]
    test ecx, ecx
    jz callTarget
copy:
    dec ecx
    push DWORD PTR [esi + ecx * 8]
    jnz copy
callTarget:
    call ebx
    lea esp, [ebp - 8]
    pop esi
    pop ebx
    pop ebp
    ret
InvokeIntegerArguments ENDP

InvokeNativeArguments PROC
    push ebp
    mov ebp, esp
    push ebx
    push esi
    mov ebx, [ebp + 8]
    mov esi, [ebp + 12]
    mov ecx, [ebp + 16]
    test ecx, ecx
    jz target
arguments:
    dec ecx
    push DWORD PTR [esi + ecx * 8]
    jnz arguments
target:
    mov eax, [ebp + 28]
    test eax, eax
    jz callNative
    mov ecx, [eax]
    mov edx, [eax + 4]
callNative:
    call ebx
    mov esi, [ebp + 20]
    mov [esi], eax
    mov [esi + 4], edx
    cmp DWORD PTR [ebp + 24], 8
    je floating64
    cmp DWORD PTR [ebp + 24], 4
    jne finished
    fstp DWORD PTR [esi + 8]
    jmp finished
floating64:
    fstp QWORD PTR [esi + 8]
finished:
    lea esp, [ebp - 8]
    pop esi
    pop ebx
    pop ebp
    ret
InvokeNativeArguments ENDP
END

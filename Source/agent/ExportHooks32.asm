.686P
.XMM
.MODEL FLAT, C
OPTION CASEMAP:NONE
EXTERN DispatchExportHook:PROC
.code

ExportHookEntry PROC
    push ebp
    mov ebp, esp
    sub esp, 40
    mov [ebp - 8], ecx
    mov [ebp - 4], edx
    lea edx, [ebp + 4]
    mov [ebp - 40], edx
    lea edx, [ebp - 40]
    push edx
    push eax
    call DispatchExportHook
    add esp, 8
    test eax, eax
    jnz bypass

    ; Relocate the return address over arguments owned by a stdcall callee.
    mov edx, [ebp - 16]
    lea edx, [ebp + edx + 4]
    mov ecx, [ebp + 4]
    mov [edx], ecx
    mov ecx, edx
    cmp DWORD PTR [ebp - 12], 8
    je floating64
    cmp DWORD PTR [ebp - 12], 4
    jne result
    fld DWORD PTR [ebp - 24]
    jmp result
floating64:
    fld QWORD PTR [ebp - 24]
result:
    mov eax, [ebp - 32]
    mov edx, [ebp - 28]
    mov esp, ebp
    pop ebp
    mov esp, ecx
    ret
bypass:
    mov ecx, [ebp - 8]
    mov edx, [ebp - 4]
    mov esp, ebp
    pop ebp
    jmp eax
ExportHookEntry ENDP
END

.686P
.MODEL FLAT, C
OPTION CASEMAP:NONE
EXTERN AsyncCallbackDispatch:PROC
.code

AsyncCallbackGateway PROC
    push ebp
    mov ebp, esp
    push eax

    ; Callback observations use fixed-width wire values before forwarding the native ABI.
    push eax
    xor ecx, ecx
    cmp DWORD PTR [eax + 20], 3
    jne fourth
    mov ecx, [ebp + 20]
fourth:
    push 0
    push ecx
    push 0
    push DWORD PTR [ebp + 16]
    push 0
    push DWORD PTR [ebp + 12]
    push 0
    push DWORD PTR [ebp + 8]
    call AsyncCallbackDispatch
    add esp, 36
    mov eax, [ebp - 4]
    cmp DWORD PTR [eax + 20], 3
    mov esp, ebp
    pop ebp
    je winsock
    ret 12
winsock:
    ret 16
AsyncCallbackGateway ENDP
END

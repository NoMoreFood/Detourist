.686P
.MODEL FLAT
OPTION CASEMAP:NONE
ASSUME FS:NOTHING
.code

_SymbolSyscall@40 PROC
    push ebp
    mov ebp, esp
    mov ecx, 9
arguments:
    push DWORD PTR [ebp + ecx * 4 + 4]
    loop arguments
    mov eax, DWORD PTR [ebp + 44]
    call service
    pop ebp
    ret 40
service:
    mov edx, OFFSET SymbolServiceGate
    call edx
    ret 36
_SymbolSyscall@40 ENDP

SymbolServiceGate PROC
    jmp DWORD PTR fs:[0C0h]
SymbolServiceGate ENDP
END

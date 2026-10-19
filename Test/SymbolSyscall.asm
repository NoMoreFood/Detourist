OPTION CASEMAP:NONE
.code
SymbolSyscall PROC
    mov r10, rcx
    mov eax, DWORD PTR [rsp + 50h]
    syscall
    ret
SymbolSyscall ENDP
END

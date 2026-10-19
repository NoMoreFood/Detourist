OPTION CASEMAP:NONE
.code
CallNativeStackProbe PROC
    mov rax, rcx
    sub rsp, 28h
    call rdx
    add rsp, 28h
    ret
CallNativeStackProbe ENDP
END

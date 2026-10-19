OPTION CASEMAP:NONE
EXTERN AsyncCallbackDispatch:PROC
.code

AsyncCallbackGateway PROC FRAME
    sub rsp, 56
    .allocstack 56
    .endprolog
    mov [rsp + 32], r10
    call AsyncCallbackDispatch
    add rsp, 56
    ret
AsyncCallbackGateway ENDP
END

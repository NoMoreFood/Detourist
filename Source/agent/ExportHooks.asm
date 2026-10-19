OPTION CASEMAP:NONE
EXTERN DispatchExportHook:PROC
.code

ExportHookEntry PROC FRAME
    sub rsp, 152
    .allocstack 152
    .endprolog

    ; Preserve both register classes so bypassed calls retain their complete incoming ABI.
    mov [rsp + 32], rcx
    mov [rsp + 40], rdx
    mov [rsp + 48], r8
    mov [rsp + 56], r9
    movdqu XMMWORD PTR [rsp + 64], xmm0
    movdqu XMMWORD PTR [rsp + 80], xmm1
    movdqu XMMWORD PTR [rsp + 96], xmm2
    movdqu XMMWORD PTR [rsp + 112], xmm3
    lea rax, [rsp + 152]
    mov [rsp + 128], rax
    mov rcx, r10
    lea rdx, [rsp + 32]
    call DispatchExportHook
    test rax, rax
    jnz bypass
    mov rax, [rsp + 136]
    movq xmm0, QWORD PTR [rsp + 144]
    add rsp, 152
    ret

bypass:
    mov r11, rax
    mov rcx, [rsp + 32]
    mov rdx, [rsp + 40]
    mov r8, [rsp + 48]
    mov r9, [rsp + 56]
    movdqu xmm0, XMMWORD PTR [rsp + 64]
    movdqu xmm1, XMMWORD PTR [rsp + 80]
    movdqu xmm2, XMMWORD PTR [rsp + 96]
    movdqu xmm3, XMMWORD PTR [rsp + 112]
    add rsp, 152
    jmp r11
ExportHookEntry ENDP
END

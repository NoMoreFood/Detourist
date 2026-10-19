OPTION CASEMAP:NONE
EXTERN __chkstk:PROC
.code

InvokeIntegerArguments PROC FRAME
    push rbp
    .pushreg rbp
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    sub rsp, 32
    .allocstack 32
    mov rbp, rsp
    .setframe rbp, 0
    .endprolog

    ; A fixed frame pointer keeps dynamic argument storage unwindable.
    mov rbx, rcx
    mov rsi, rdx
    mov r12, r8
    mov r13, r9
    mov r14, [rbp + 128]
    lea rax, [r12 + r14]
    lea rax, [rax * 8 + 15]
    and rax, -16
    call __chkstk
    sub rsp, rax

    ; Copy the editable prefix and the complete uncaptured tail into the callee's parameter area.
    mov rdi, rsp
    mov rcx, r12
    rep movsq
    mov rsi, r13
    mov rcx, r14
    rep movsq
    mov rcx, [rsp]
    mov rdx, [rsp + 8]
    mov r8, [rsp + 16]
    mov r9, [rsp + 24]
    call rbx

    lea rsp, [rbp + 32]
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
InvokeIntegerArguments ENDP

InvokeNativeArguments PROC FRAME
    push rbp
    .pushreg rbp
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    sub rsp, 40
    .allocstack 40
    mov rbp, rsp
    .setframe rbp, 0
    .endprolog

    ; Keep the call and result storage in nonvolatile registers across the target's execution.
    mov rbx, rcx
    mov rsi, rdx
    mov r12, r8
    mov r13, r9
    lea rax, [r12 * 8 + 15]
    and rax, -16
    call __chkstk
    sub rsp, rax
    mov rdi, rsp
    mov rcx, r12
    rep movsq

    ; Win64 assigns each register position to its integer or floating-point register class.
    mov rcx, [rsp]
    mov rdx, [rsp + 8]
    mov r8, [rsp + 16]
    mov r9, [rsp + 24]
    movq xmm0, QWORD PTR [rsp]
    movq xmm1, QWORD PTR [rsp + 8]
    movq xmm2, QWORD PTR [rsp + 16]
    movq xmm3, QWORD PTR [rsp + 24]
    call rbx
    mov [r13], rax
    movq QWORD PTR [r13 + 8], xmm0

    lea rsp, [rbp + 40]
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
InvokeNativeArguments ENDP
END

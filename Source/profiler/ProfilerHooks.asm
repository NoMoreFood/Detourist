OPTION CASEMAP:NONE

EXTERN DetouristManagedEnter:PROC
EXTERN DetouristManagedLeave:PROC
EXTERN DetouristManagedTailcall:PROC
EXTERN DetouristManagedEnter2:PROC
EXTERN DetouristManagedLeave2:PROC
EXTERN DetouristManagedTailcall2:PROC
EXTERN ManagedXStateMask:DWORD
EXTERN ManagedXStateBytes:DWORD

.code

; CLR enter/leave hooks require preservation beyond the normal volatile-register ABI.
MANAGED_HOOK MACRO name, target
PUBLIC name
name PROC FRAME
    push rbp
    .pushreg rbp
    sub rsp, 80h
    .allocstack 80h
    lea rbp, [rsp+80h]
    .setframe rbp, 80h
    .endprolog
    mov [rbp-08h], rax
    mov [rbp-10h], rcx
    mov [rbp-18h], rdx
    mov [rbp-20h], r8
    mov [rbp-28h], r9
    mov [rbp-30h], r10
    mov [rbp-38h], r11
    mov eax, ManagedXStateBytes
    add rax, 7Fh
    sub rsp, rax
    and rsp, -64
    cmp ManagedXStateMask, 0
    je name&_fxsave
    xor eax, eax
    mov [rsp+240h], rax
    mov [rsp+248h], rax
    mov [rsp+250h], rax
    mov [rsp+258h], rax
    mov [rsp+260h], rax
    mov [rsp+268h], rax
    mov [rsp+270h], rax
    mov [rsp+278h], rax
    mov eax, ManagedXStateMask
    xor edx, edx
    xsave64 [rsp+40h]
    jmp name&_saved
name&_fxsave:
    fxsave64 [rsp+40h]
name&_saved:
    mov rcx, [rbp-10h]
    mov rdx, [rbp-18h]
    mov r8, [rbp-20h]
    mov r9, [rbp-28h]
    call target
    cmp ManagedXStateMask, 0
    je name&_fxrestore
    mov eax, ManagedXStateMask
    xor edx, edx
    xrstor64 [rsp+40h]
    jmp name&_restored
name&_fxrestore:
    fxrstor64 [rsp+40h]
name&_restored:
    mov rax, [rbp-08h]
    mov rcx, [rbp-10h]
    mov rdx, [rbp-18h]
    mov r8, [rbp-20h]
    mov r9, [rbp-28h]
    mov r10, [rbp-30h]
    mov r11, [rbp-38h]
    lea rsp, [rbp]
    pop rbp
    ret
name ENDP
ENDM

MANAGED_HOOK ManagedEnterStub, DetouristManagedEnter
MANAGED_HOOK ManagedLeaveStub, DetouristManagedLeave
MANAGED_HOOK ManagedTailcallStub, DetouristManagedTailcall
MANAGED_HOOK ManagedEnter2Stub, DetouristManagedEnter2
MANAGED_HOOK ManagedLeave2Stub, DetouristManagedLeave2
MANAGED_HOOK ManagedTailcall2Stub, DetouristManagedTailcall2

END

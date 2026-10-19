.686P
.XMM
.MODEL FLAT, C
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

; CLR enter/leave hooks preserve the application's integer, flags and enabled floating-point state.
MANAGED_HOOK MACRO name, target, arguments
PUBLIC name
name PROC
    push ebp
    mov ebp, esp
    pushfd
    pushad
    mov eax, ManagedXStateBytes
    add eax, 63
    sub esp, eax
    and esp, -64
    mov esi, esp
    cmp ManagedXStateMask, 0
    je name&_fxsave
    lea edi, [esi+512]
    xor eax, eax
    mov ecx, 16
    rep stosd
    mov eax, ManagedXStateMask
    xor edx, edx
    xsave [esi]
    jmp name&_saved
name&_fxsave:
    fxsave [esi]
name&_saved:
    mov ecx, arguments
name&_argument:
    push DWORD PTR [ebp+ecx*4+4]
    loop name&_argument
    call target
    add esp, arguments*4
    cmp ManagedXStateMask, 0
    je name&_fxrestore
    mov eax, ManagedXStateMask
    xor edx, edx
    xrstor [esi]
    jmp name&_restored
name&_fxrestore:
    fxrstor [esi]
name&_restored:
    lea esp, [ebp-36]
    popad
    popfd
    pop ebp
    ret arguments*4
name ENDP
ENDM

MANAGED_HOOK ManagedEnterStub, DetouristManagedEnter, 2
MANAGED_HOOK ManagedLeaveStub, DetouristManagedLeave, 2
MANAGED_HOOK ManagedTailcallStub, DetouristManagedTailcall, 2
MANAGED_HOOK ManagedEnter2Stub, DetouristManagedEnter2, 4
MANAGED_HOOK ManagedLeave2Stub, DetouristManagedLeave2, 4
MANAGED_HOOK ManagedTailcall2Stub, DetouristManagedTailcall2, 3

END

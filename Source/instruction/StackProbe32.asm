.686P
.MODEL FLAT
OPTION CASEMAP:NONE

.code

; Probe and allocate on the runtime's actual stack instead of the application's TEB stack limits.
PUBLIC _chkstk
_chkstk PROC
    push ecx
    lea ecx, [esp+8]
    cmp eax, 1000h
    jb last_page
next_page:
    sub ecx, 1000h
    test DWORD PTR [ecx], eax
    sub eax, 1000h
    cmp eax, 1000h
    jae next_page
last_page:
    sub ecx, eax
    test DWORD PTR [ecx], eax
    mov eax, esp
    mov esp, ecx
    mov ecx, [eax]
    mov eax, [eax+4]
    push eax
    ret
_chkstk ENDP

END

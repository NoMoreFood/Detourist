OPTION CASEMAP:NONE

.code

; Probe the runtime's actual stack; the TEB limit can describe a higher application fiber stack.
PUBLIC __chkstk
__chkstk PROC FRAME
    sub rsp, 10h
    .allocstack 10h
    .endprolog
    mov [rsp], r10
    mov [rsp+8], r11
    mov r10, rax
    lea r11, [rsp+18h]
    cmp r10, 1000h
    jb last_page
next_page:
    sub r11, 1000h
    test byte ptr [r11], 0
    sub r10, 1000h
    cmp r10, 1000h
    jae next_page
last_page:
    sub r11, r10
    test byte ptr [r11], 0
    mov r10, [rsp]
    mov r11, [rsp+8]
    add rsp, 10h
    ret
__chkstk ENDP

END

main:
    lea     rdi, [rip+msg]          // rdi <- msg
    mov     rsi, [r15+40]           // rsi <- stderr
    call    qword ptr [r15+168]     // fputs(rdi, rsi)
    
    mov     edi, 69                 // edi <- 69
    call    qword ptr [r15+80]      // exit(edi)

msg: .asciz  "hello there\n"

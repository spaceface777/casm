main:
    adr	    x0, msg          // x0 <- msg
    ldr     x1, [x28, 40]    // x1 <- stderr
    ldr     x9, [x28, 168]   // x9 <- fputs
    blr     x9               // x9(x0, x1)
    
    mov     w0, 69           // x0 <- 69
    ldr     x9, [x28, 80]    // x9 <- exit
    blr     x9               // x9(x0)

msg: .asciz  "hello there\n"

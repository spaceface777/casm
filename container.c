#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __APPLE__
#define TEXT_SECTION __attribute__((section("__TEXT,__text")))
#else
#define TEXT_SECTION __attribute__((section(".text#")))
#endif

#ifndef CODE_SIZE
#define CODE_SIZE 1000000
#endif

TEXT_SECTION volatile const char CODE_BYTES[CODE_SIZE] = "CODE_START";
void (*CODE)(void) = (void*)CODE_BYTES;

volatile void* DATA_TABLE[] = {
    0, // argc              // +0
    0, // argv              // +8
    0, // envp              // +16
    0, // stdin             // +24
    0, // stdout            // +32
    0, // stderr            // +40

    // syscalls
    read,                   // +48
    write,                  // +56
    fopen,                  // +64
    fclose,                 // +72
    exit,                   // +80
    
    // libc
    malloc,                 // +88
    free,                   // +96
    memset,                 // +104
    memcpy,                 // +112
    memmove,                // +120
    memcmp,                 // +128
    strlen,                 // +136
    strcpy,                 // +144
    strcmp,                 // +152
    puts,                   // +160
    fputs,                  // +168
    printf,                 // +176
    fprintf,                // +184
};


int main(int argc, char** argv, char** envp) {
    DATA_TABLE[0] = (void*)(size_t)argc;
    DATA_TABLE[1] = (void*)(size_t)argv;
    DATA_TABLE[2] = (void*)(size_t)envp;
    DATA_TABLE[3] = stdin;
    DATA_TABLE[4] = stdout;
    DATA_TABLE[5] = stderr;

#if defined(__x86_64__) || defined(_M_AMD64)
    __asm__ __volatile__(
        "movq %1,%%r15\n"
        "call *%0\n"
        : // output
        : "g"(CODE), "X"(DATA_TABLE) // input
        : "rax", "rbx", "rcx", "rdx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    );
#elif defined(__aarch64__) || defined(__arm64__) || defined(_M_ARM64)
    __asm__ __volatile__(
        "mov  x28, %1\n"
        "blr   %0\n"
        : // output
        : "r"(CODE), "X"(DATA_TABLE) // input
        : "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x28", "cc", "memory"
    );
#else
    #error "Unsupported architecture"
#endif
}
x
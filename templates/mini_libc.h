/*
 * mini_libc.h - freestanding i386 support header for Reverse Tutor challenges.
 *
 * The challenge is built for **32-bit** Linux (i386) with no C library: the entry
 * point is our own `_start` and every kernel service is reached through
 * `int $0x80` with the syscall number in `EAX` and the arguments in
 * `EBX, ECX, EDX, ESI, EDI, EBP`.
 *
 * Two reasons this file exists rather than a normal `#include <unistd.h>`:
 *
 * 1. It makes the challenge buildable from a Windows host with nothing but
 *    clang + lld — there is no i386 Linux sysroot anywhere on the machine, and a
 *    freestanding program needs none.
 * 2. It keeps the disassembly honest. Every helper here is plain C whose compiled
 *    form is the textbook i386 shape a 32-bit reverse-engineering student is
 *    learning to read: `push ebp / mov ebp, esp / sub esp, N`, a counted loop in
 *    `ECX`, `movzx eax, byte ptr [eax+edx]`, and `int 0x80` for kernel calls.
 *
 * Nothing here hides control flow.
 */
#ifndef REVERSE_TUTOR_MINI_LIBC_H
#define REVERSE_TUTOR_MINI_LIBC_H

typedef unsigned int rt_size_t;
typedef int rt_ssize_t;

/* i386 Linux syscall numbers (asm/unistd_32.h). */
#define RT_SYS_READ 3
#define RT_SYS_WRITE 4
#define RT_SYS_EXIT 1

/* File descriptors we need. */
#define RT_STDIN 0
#define RT_STDOUT 1

/* Longest accepted input line, including the terminating NUL. */
#define RT_MAX_LINE 256

/*
 * One `int $0x80` with EAX = number and EBX/ECX/EDX = arguments.
 *
 * `memory` is listed as clobbered because the kernel reads and writes the buffers
 * those registers point at, and the compiler must not reorder loads across it.
 */
static inline int rt_syscall3(int number, int a0, int a1, int a2)
{
    int result;
    __asm__ volatile("int $0x80"
                     : "=a"(result)
                     : "a"(number), "b"(a0), "c"(a1), "d"(a2)
                     : "memory");
    return result;
}

/* write(2) via the kernel directly. */
static int rt_write(int fd, const char *buffer, rt_size_t length)
{
    return rt_syscall3(RT_SYS_WRITE, fd, (int)buffer, (int)length);
}

/* read(2) via the kernel directly. */
static int rt_read(int fd, char *buffer, rt_size_t length)
{
    return rt_syscall3(RT_SYS_READ, fd, (int)buffer, (int)length);
}

/* Print a NUL-terminated string. */
static void rt_puts(const char *text)
{
    rt_size_t length = 0;
    while (text[length] != '\0') {
        length++;
    }
    if (length > 0) {
        rt_write(RT_STDOUT, text, length);
    }
}

/* String length, spelled out so the loop body is visible in the disassembly. */
static rt_size_t rt_strlen(const char *text)
{
    rt_size_t length = 0;
    while (text[length] != '\0') {
        length++;
    }
    return length;
}

/*
 * Read one line from stdin into `out` (size RT_MAX_LINE) and return its length.
 * A trailing LF and an optional CR are removed; the buffer is always NUL
 * terminated. Returns -1 when the read fails.
 */
static int rt_read_line(char *out)
{
    int count = rt_read(RT_STDIN, out, RT_MAX_LINE - 1);
    if (count <= 0) {
        out[0] = '\0';
        return count;
    }

    int length = 0;
    while (length < count && out[length] != '\n') {
        length++;
    }
    if (length > 0 && out[length - 1] == '\r') {
        length--;
    }
    out[length] = '\0';
    return length;
}

/* Terminate the process with `code`; replaces exit(3). */
static void rt_exit(int code)
{
    rt_syscall3(RT_SYS_EXIT, code, 0, 0);
    for (;;) {
        /* rt_exit never returns. */
    }
}

/*
 * Process entry point.
 *
 * The kernel enters here with the stack holding argc at [esp], argv at [esp+4],
 * and so on. cdecl needs ESP aligned before a `call` pushes the return address, so
 * ESP is rounded down first — the same prologue 32-bit gcc emits. The return value
 * of rt_main becomes the process exit status, which is exactly the contract the
 * verifier reads: 0 means the accepted value was entered.
 */
int rt_main(void);

__attribute__((naked, used)) void _start(void)
{
    __asm__ volatile("andl $-16, %esp\n\t"
                     "call rt_main\n\t"
                     "movl %eax, %ebx\n\t"
                     "movl $1, %eax\n\t"
                     "int $0x80\n\t"
                     "hlt\n\t");
}

#endif /* REVERSE_TUTOR_MINI_LIBC_H */

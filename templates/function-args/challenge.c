/*
 * Challenge: function-args
 *
 * Teaching goal: apply the **cdecl** calling convention on 32-bit x86. Push order,
 * `[ebp+8]` / `[ebp+0xc]` / `[ebp+0x10]`, and who cleans the stack up are the whole
 * point of this exercise.
 *
 * Three digest functions each receive ONE argument. Recovering the accepted value
 * means working out which stack slot holds which slice, then reassembling them in
 * argument order — the class of reasoning that does not exist in 64-bit code,
 * where the first arguments arrive in registers instead.
 *
 * Analysis hints are NOT in this file on purpose. Open the built ELF in IDA Pro.
 */
#include "mini_libc.h"

/*
 * The accepted length. The build rewrites this to match the generated secret, so
 * it is deliberately not "the answer": the length tells a student how many bytes
 * to recover, never which ones.
 */
#define RT_SECRET_LENGTH 12

#define RT_SLICE_A 5
#define RT_SLICE_B 4

/*__RT_DEFINES__*/

/*
 * Three digest functions, one per argument. Each walks its own slice and folds it
 * into an integer; `rt_check` compares the three results against the reference
 * values.
 *
 * Every callee reads its argument from `[ebp+8]`, because that is where cdecl puts
 * the first (and here only) argument: the caller's `call` pushed the return address
 * to `[ebp+4]` first.
 */

/* Fold a byte slice with a shift-and-xor recurrence. */
static int rt_digest_a(const char *slice)
{
    int accumulator = 0;

    for (int index = 0; index < RT_SLICE_A; ++index) {
        accumulator = (accumulator << 3) ^ (int)(unsigned char)slice[index];
    }

    return accumulator;
}

/* Fold a byte slice with a shift-and-add recurrence whose shift depends on the index. */
static int rt_digest_b(const char *slice)
{
    int accumulator = 0;

    for (int index = 0; index < RT_SLICE_B; ++index) {
        accumulator = accumulator + ((int)(unsigned char)slice[index] << (index + 1));
    }

    return accumulator;
}

/* Fold a NUL-terminated slice with a multiply-and-add recurrence. */
static int rt_digest_c(const char *slice)
{
    int accumulator = 0;
    int index = 0;

    while (slice[index] != '\0') {
        accumulator = accumulator * 5 + (int)(unsigned char)slice[index];
        index++;
    }

    return accumulator + index;
}

/*
 * The caller. Three things are worth reading in the disassembly:
 *
 * 1. the `push` before each `call` — cdecl pushes arguments right to left;
 * 2. the `add esp, 4` after each `call` — the CALLER cleans the stack, not the
 *    callee, which is the property that defines cdecl;
 * 3. `input + RT_SLICE_A` and `input + RT_SLICE_A + RT_SLICE_B` — plain pointer
 *    arithmetic producing the second and third slices of one buffer.
 */
static int rt_check(const char *a, const char *b, const char *c)
{
    if (rt_digest_a(a) != rt_target_a) {
        return 0;
    }

    if (rt_digest_b(b) != rt_target_b) {
        return 0;
    }

    if (rt_digest_c(c) != rt_target_c) {
        return 0;
    }

    return 1;
}

int rt_main(void)
{
    char input[RT_MAX_LINE];

    rt_puts("== Reverse Tutor :: function-args (cdecl) ==\n");
    rt_puts("Enter the accepted value: ");

    if (rt_read_line(input) <= 0) {
        rt_puts("no input\n");
        return 2;
    }

    if (rt_strlen(input) != RT_SECRET_LENGTH) {
        rt_puts("rejected\n");
        return 1;
    }

    const char *slice_a = input;
    const char *slice_b = input + RT_SLICE_A;
    const char *slice_c = input + RT_SLICE_A + RT_SLICE_B;

    if (rt_check(slice_a, slice_b, slice_c) != 0) {
        rt_puts("accepted\n");
        return 0;
    }

    rt_puts("rejected\n");
    return 1;
}

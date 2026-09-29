/*
 * Challenge: xor-loop
 *
 * Teaching goal: recognise a byte-wise XOR transform, trace where the input
 * bytes come from, recover the key, then invert the transform to recover the
 * accepted input.
 *
 * Analysis hints are NOT in this file on purpose. Open the built ELF in IDA Pro
 * and let the instructions speak.
 */
#include "mini_libc.h"

/*
 * The accepted length. The build rewrites this to match the generated secret, so
 * it is deliberately not "the answer": the length tells a student how many bytes
 * to recover, never which ones.
 */
#define RT_SECRET_LENGTH 12

/*__RT_DEFINES__*/

/*
 * Verification function. Returns 1 when `input` is the accepted value and 0
 * otherwise. The comparison is deliberately written as an explicit byte loop so
 * the transform and the reference bytes are both visible in the disassembly.
 */
static int rt_check(const char *input)
{
    for (int index = 0; index < RT_SECRET_LENGTH; ++index) {
        unsigned char mixed = (unsigned char)(input[index] ^ rt_key[index % RT_KEY_WIDTH]);
        if (mixed != rt_target[index]) {
            return 0;
        }
    }

    return input[RT_SECRET_LENGTH] == '\0';
}

int rt_main(void)
{
    char input[RT_MAX_LINE];

    rt_puts("== Reverse Tutor :: xor-loop ==\n");
    rt_puts("Enter the accepted value: ");

    if (rt_read_line(input) <= 0) {
        rt_puts("no input\n");
        return 2;
    }

    if (rt_check(input) != 0) {
        rt_puts("accepted\n");
        return 0;
    }

    rt_puts("rejected\n");
    return 1;
}

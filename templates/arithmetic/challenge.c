/*
 * Challenge: arithmetic
 *
 * Teaching goal: follow integer arithmetic on character data, keep track of
 * operand order, and invert a per-index computation — including the part that
 * advances as the loop runs.
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

/*__RT_DEFINES__*/

/*
 * The reference array holds `(input[i] + i) * RT_SCALE - bias` for every index,
 * where `bias` starts at RT_BIAS and grows by RT_BIAS_STEP on each iteration. The
 * accepted input is recovered by undoing that expression in the reverse order,
 * and by noticing that the bias is not constant.
 */
static int rt_check(const char *input)
{
    int bias = RT_BIAS;

    for (int index = 0; index < RT_SECRET_LENGTH; ++index) {
        int value = ((int)(unsigned char)input[index] + index) * RT_SCALE - bias;

        if (value != rt_target[index]) {
            return 0;
        }

        bias += RT_BIAS_STEP;
    }

    return input[RT_SECRET_LENGTH] == '\0';
}

int rt_main(void)
{
    char input[RT_MAX_LINE];

    rt_puts("== Reverse Tutor :: arithmetic ==\n");
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

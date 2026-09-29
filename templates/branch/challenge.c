/*
 * Challenge: branch
 *
 * Teaching goal: read a `cmp`/`jcc` decision shape, work out which comparison
 * actually selects the accepting path, and invert it differently on each side.
 *
 * The interesting part is not the arithmetic — it is that a range test and an
 * equality test look almost the same once compiled, and only one of them can be
 * inverted by undoing an expression. The range branch is checked FIRST, so a byte
 * inside it never reaches the affine transforms a reader expects from the source.
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

static int rt_check(const char *input)
{
    for (int index = 0; index < RT_SECRET_LENGTH; ++index) {
        unsigned char current = (unsigned char)input[index];

        if (current == 0) {
            return 0;
        }

        if (current >= RT_GATE && current < RT_GATE + RT_WINDOW_WIDTH) {
            if ((int)current != rt_target[index]) {
                return 0;
            }
            continue;
        }

        if (current < RT_GATE) {
            if ((int)current - RT_BIAS_LOW != rt_target[index]) {
                return 0;
            }
            continue;
        }

        if ((int)current + RT_BIAS_HIGH != rt_target[index]) {
            return 0;
        }
    }

    return input[RT_SECRET_LENGTH] == '\0';
}

int rt_main(void)
{
    char input[RT_MAX_LINE];

    rt_puts("== Reverse Tutor :: branch ==\n");
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

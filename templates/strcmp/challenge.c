/*
 * Challenge: strcmp
 *
 * Teaching goal: recognise a byte-wise equality loop, decide which operand is
 * attacker-controlled, and see where the reference bytes actually come from.
 *
 * The reference bytes are NOT a plain string literal. They are generated at run
 * time from a 64-bit recurrence and then XORed with the input, so reading
 * `.rodata` gives bytes but not meaning: the accepted value has to be recovered
 * from the code that produces and consumes them.
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
 * One step of the recurrence, kept as a separate function so the compiled
 * `imul`/`add` pair is visible rather than inlined into the loop.
 *
 * i386 has no 64-bit register file, so a compiler spells this as a pair of 32-bit
 * multiplies and a carry — which is the point: the reader has to see that the
 * state is 64 bits wide even though the machine is 32 bits wide.
 */
static unsigned long long rt_step(unsigned long long state)
{
    return state * RT_KEY_MUL + RT_KEY_INC;
}

/*
 * Produce the byte the recurrence contributes at `index`. The shift is a compile
 * time constant, so this is a fixed extraction rather than a variable shift.
 */
static unsigned char rt_keystream(unsigned long long state)
{
    return (unsigned char)((state >> RT_KEY_SHIFT) & 0xffull);
}

/*
 * Materialise the stored reference into bytes.
 *
 * The two shapes are the two difficulty variants, and they are selected at compile
 * time: the encoder defines exactly one of `rt_target` and `rt_target_words`, so a
 * runtime test would not compile. The word shape is the one that forces a reader to
 * state the byte order exactly instead of guessing it.
 */
static void rt_materialise(unsigned char *out)
{
#if RT_PACK_WORDS
    for (int index = 0; index < RT_SECRET_LENGTH; ++index) {
        out[index] = (unsigned char)((rt_target_words[index / 4] >> ((index % 4) * 8)) & 0xffu);
    }
#else
    for (int index = 0; index < RT_SECRET_LENGTH; ++index) {
        out[index] = (unsigned char)rt_target[index];
    }
#endif
}

/*
 * Compare `input` against the reference, byte by byte. The reference byte is not
 * the accepted byte: it is `accepted ^ keystream`, so recovering the accepted
 * value needs both the table and the recurrence that generated the keystream.
 */
static int rt_compare(const char *input)
{
    unsigned char reference[RT_SECRET_LENGTH];
    rt_materialise(reference);

    unsigned long long state = RT_KEY_SEED;
    int index = 0;

    for (;;) {
        state = rt_step(state);

        unsigned char left = (unsigned char)((unsigned char)input[index] ^ rt_keystream(state));
        unsigned char right = reference[index];

        if (left != right) {
            return 0;
        }

        if ((unsigned char)input[index] == '\0') {
            break;
        }

        index++;
        if (index >= RT_SECRET_LENGTH) {
            break;
        }
    }

    return 1;
}

int rt_main(void)
{
    char input[RT_MAX_LINE];

    rt_puts("== Reverse Tutor :: strcmp ==\n");
    rt_puts("Enter the accepted value: ");

    if (rt_read_line(input) <= 0) {
        rt_puts("no input\n");
        return 2;
    }

    if (rt_compare(input) != 0) {
        rt_puts("accepted\n");
        return 0;
    }

    rt_puts("rejected\n");
    return 1;
}

# arithmetic

| field | value |
|---|---|
| topic | `integer-arithmetic` |
| difficulties | `beginner`, `intermediate` |
| binary | `challenge` (ELF64 x86-64, freestanding, PIE off, symbol table stripped) |
| verification | `./challenge <candidate>` exits 0 on acceptance |

## What the student must recover

The accepted input string, encoded into an `int` reference array by
`(input[i] + i) * RT_SCALE - RT_BIAS`.

## Teaching objectives

1. Read a compiled arithmetic expression and restate it as an expression.
2. Keep the operand order straight: which term is the input byte, which is the
   index, and in which order the multiply and subtract apply.
3. Invert the whole expression over the reference array, in the reverse order of
   operations.
4. Explain why the `unsigned char` load is sign-extended here and what would
   change if it were not.
5. Notice that the reference array is wider than a byte, so the `.rodata` dump is
   not directly the answer.

## Difficulty knobs

| level | scale | bias | array element width |
|---|---|---|---|
| `beginner` | 3 | 7 | `int` (4 bytes) |
| `intermediate` | 5 | per-index, incremented inside the loop | `int` (4 bytes) |

## Expected mistakes

- Reading the raw `int` array as ASCII and reporting garbage.
- Dividing before adding the bias back, instead of undoing the bias first.
- Missing the decrement of the reference array pointer and therefore indexing
  the array in reverse.

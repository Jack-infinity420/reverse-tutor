# xor-loop

| field | value |
|---|---|
| topic | `xor` |
| difficulties | `beginner`, `intermediate` |
| binary | `challenge` (ELF64 x86-64, freestanding, PIE off, symbol table stripped) |
| verification | `./challenge <candidate>` exits 0 on acceptance |

## What the student must recover

The accepted input string. It is never present in the source, the delivered
`challenge.c`, or the binary as plain text: the build injects only the
XOR-mixed reference bytes, so the value has to be recovered by inverting the
transform found in the disassembly.

## Teaching objectives

1. Identify the XOR transform in `rt_check` (or whatever IDA names it).
2. Prove where the transformed bytes come from — that is, that the loop walks
   the caller's input buffer rather than any global.
3. Recover the XOR key and its width.
4. Invert the transform over the reference array and reconstruct the input.
5. Notice that `int` and `unsigned char` narrowing changes what the comparison
   actually tests (difficulty `intermediate` only).

## Difficulty knobs

| level | key | key layout | extra twist |
|---|---|---|---|
| `beginner` | 1 byte | broadcast over the whole string | none |
| `intermediate` | 4 bytes | one key byte per index `mod 4` | the two halves of the loop are split into a helper call |

## Expected mistakes

- Reporting the mixed reference bytes from `.rodata` as the answer.
- Assuming the key repeats over a stride they guessed instead of the one the
  code uses.
- Reading the `unsigned char` cast as a no-op.

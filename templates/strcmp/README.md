# strcmp

| field | value |
|---|---|
| topic | `string-comparison` |
| difficulties | `beginner`, `intermediate` |
| binary | `challenge` (ELF64 x86-64, freestanding, PIE off, symbol table stripped) |
| verification | `./challenge <candidate>` exits 0 on acceptance |

## What the student must recover

The accepted input string.

## Teaching objectives

1. Recognise the byte-wise equality idiom (`movzx` / `cmp` / `jne` inside a
   loop) and say what it means.
2. Decide which operand of the comparison is derived from user input, and prove
   it by tracing the argument from the caller's buffer.
3. Follow the constant pointer into `.rodata` and recover the reference string.
4. Understand why "the transform is trivial" does not make a challenge trivial:
   locating the constant is the actual work.
5. Explain the loop's second exit condition — the `'\0'` check that makes a
   prefix of the reference insufficient.

## Difficulty knobs

| level | reference bytes | width | extra twist |
|---|---|---|---|
| `beginner` | visible as a literal `char[]` initialiser in `.rodata` | 1 byte per char | the loop is fully inlined in one function |
| `intermediate` | stored as `unsigned int` words, later narrowed back to bytes | 4 bytes per store | recovery requires reading the exact byte order |

## Expected mistakes

- Reading the obfuscated word representation and reporting the raw integers.
- Answering a prefix that satisfies the first comparison but fails the `'\0'`
  check.
- Claiming the comparison is a length check because a `strlen`-looking helper
  exists in the binary.

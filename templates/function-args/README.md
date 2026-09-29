# function-args

| field | value |
|---|---|
| topic | `calling-convention` |
| difficulties | `beginner`, `intermediate` |
| binary | `challenge` (ELF64 x86-64, freestanding, PIE off, symbol table stripped) |
| verification | `./challenge <candidate>` exits 0 on acceptance |

## What the student must recover

The accepted input string, which is split into three slices and checked by three
independent digest functions.

## Teaching objectives

1. Apply the x86-64 System V convention: `RDI`, `RSI`, `RDX`, `RCX`, `R8`, `R9`
   for the first six integer arguments, `RAX` for the return value.
2. At the call site, prove which argument register carries which pointer, and
   show how `input + RT_SLICE_A` produces the second slice.
3. Recognise that each callee receives a pointer, not a copy, and that the
   callees therefore never see the whole string.
4. Reconstruct the three slices, then concatenate them in argument order.
5. Explain why the length check in the caller is not redundant with the digest
   loops.

## Difficulty knobs

| level | slice A | slice B | slice C | digests |
|---|---|---|---|---|
| `beginner` | 4 bytes | 4 bytes | 4 bytes | all three use the same constant-stride pattern |
| `intermediate` | 5 bytes | 4 bytes | 3 bytes | each digest has a different recurrent form, one of them is a `while` loop |

## Expected mistakes

- Reading `RSI` as `input + 5` and then assuming slice B starts at offset 5 in
  a *different* buffer.
- Recovering the digests but concatenating the slices in the wrong order.
- Treating the third digest's `+ index` term as part of the loop and inverting it
  twice.

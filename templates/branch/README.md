# branch

| field | value |
|---|---|
| topic | `control-flow` |
| difficulties | `beginner`, `intermediate` |
| binary | `challenge` (ELF64 x86-64, freestanding, PIE off, symbol table stripped) |
| verification | `./challenge <candidate>` exits 0 on acceptance |

## What the student must recover

The accepted input string, where every character has to satisfy a per-index
range test plus a small piecewise transform.

## Teaching objectives

1. Read a `cmp` / `jcc` decision tree and state, for each branch, which values
   reach it.
2. Recognise a signed comparison used as an unsigned range test and explain the
   exact range it covers.
3. Decide which branch accepts and which rejects — the confusing one is usually
   the shortcut, not the answer.
4. Invert the piecewise transform branch by branch.
5. Prove the answer is unique by showing the branches cover disjoint ranges.

## Difficulty knobs

| level | branches | transform | gate |
|---|---|---|---|
| `beginner` | two | one affine form, folded into the comparison | `RT_GATE` appears as a plain immediate |
| `intermediate` | three | two affine forms plus a byte-range test | the gate is derived from another immediate |

## Expected mistakes

- Assuming the accepting path is the more deeply nested one.
- Inverting the third branch with the second branch's constant, which still
  produces printable characters and is therefore not obviously wrong.
- Reporting a character from the shortcut branch without checking that it also
  satisfies that branch's upper bound.

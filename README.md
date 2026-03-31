# Route Cipher + Custom Hash Authentication System

## What this project does

This project implements two things and combines them into one pipeline:

1. A **Route Cipher** to encrypt and decrypt messages.
2. A **custom hash function** to verify that a message was not tampered with.

Together they form a simple send-and-receive system where the sender encrypts a message and the receiver can confirm, after decrypting, that nothing was changed in transit.

---

## Files

| File | Purpose |
|---|---|
| `route_cipher_core.py` | All the core logic: cipher, hash, sender and receiver functions |
| `test_runner.py` | Interactive terminal program to test everything manually |

---

## How to run

Make sure both files are in the same folder. Then open a terminal in that folder and run:

```bash
python test_runner.py
```

You will see a menu with three options:

- **Option 1** runs a full test. You type the message, choose the key, and decide whether to simulate a tampering attack.
- **Option 2** lets you hash any message directly and see the output.
- **Option 3** exits the program.

No installation needed. No external packages. Works on Python 3.10 and above.

---

## The Route Cipher

### What it is

A Route Cipher is a classic transposition cipher. It does not replace letters with other letters. Instead, it rearranges them by placing the message into a grid and then reading the grid in a different order. The result looks scrambled, but no substitution has happened.

### Why columnar

There are many ways to read a grid: spirals, zigzags, diagonals. We chose the **columnar route** because it is simple, predictable, and perfectly reversible without any edge-case handling for non-square grids. The sender and receiver just need to agree on one number: how many columns the grid has. That number is the key.

### How encryption works

Take the message `HELLOCRYPTOGRAPHY` with a key of `5` (5 columns).

Step 1: Write the message into the grid row by row. If the message does not fill the last row, pad it with `X`.

```
H E L L O
C R Y P T
O G R A P
H Y X X X
```

Step 2: Read the grid column by column, top to bottom.

- Column 0: H, C, O, H
- Column 1: E, R, G, Y
- Column 2: L, Y, R, X
- Column 3: L, P, A, X
- Column 4: O, T, P, X

Ciphertext: `HCOHERGYLYRXLPAXOTPX`

### How decryption works

The receiver knows the key (number of columns). They divide the ciphertext back into columns of equal length, then read row by row to get the original message back. The trailing `X` padding is stripped at the end.

---

## The Custom Hash Function

### What a hash function is

A hash function takes any input and produces a fixed-size output called a digest. The same input always gives the same digest. If you change even one character in the input, the digest changes completely. This is what makes hashes useful for detecting tampering.

### Why we built one from scratch

The assignment requires no use of `hashlib` or any built-in hash library. So we designed a simple one that follows the same general ideas used in real hash functions like MD5 or SHA, but is much simpler.

### How our hash works

The hash processes the message in chunks of 4 bytes at a time. It maintains an internal number called `state`, which starts at a fixed value (`0xDEADBEEF`). For each chunk, it applies four operations:

1. **XOR** the state with the chunk. This mixes the chunk into the state.
2. **Rotate left by 7 bits**. This spreads bits across the number so nearby chunks do not just cancel each other out.
3. **Add the chunk modulo 2^32**. This introduces non-linearity.
4. **XOR with the chunk shifted right by 3**. This adds one more avalanche step.

After all chunks are processed, a final mixing step is applied and the result is output as an 8-character hex string like `765595EB`.

Before processing, the message is:
- Encoded to bytes.
- Padded to a multiple of 4 bytes with null bytes.
- Appended with a 4-byte tag recording the original length. This prevents two different messages from accidentally producing the same sequence of blocks.

### Known limitations

This is intentionally simple and has weaknesses:

- The digest is only 32 bits long. By the birthday paradox, collisions become likely after around 65,000 different messages. Real hash functions like SHA-256 use 256-bit outputs.
- There is no salt, so the same message always produces the same hash. A real system would add a random value to prevent lookup table attacks.
- It is not designed to resist dedicated cryptanalysis.

These are acceptable for a learning exercise, and we have not hidden them.

---

## The Authentication Pipeline

### The problem it solves

Encryption hides the content of a message. But if someone intercepts and modifies the ciphertext before it reaches the receiver, the receiver would decrypt a corrupted message and not know anything went wrong. We need a way to detect that.

### How the pipeline works

**Sender side:**

1. Compute the hash of the message: `H(M)`.
2. Append the hash to the message: `M || H(M)`.
3. Encrypt the whole thing using the Route Cipher.
4. Send the ciphertext.

**Receiver side:**

1. Decrypt the ciphertext.
2. Take the last 8 characters as the received hash.
3. Take everything before those 8 characters as the recovered message.
4. Recompute the hash of the recovered message: `H'(M)`.
5. Compare `H(M)` and `H'(M)`.
   - If they match: the message is authentic and unmodified.
   - If they differ: something was changed in transit.

### Why this works

Any change to the ciphertext, even flipping a single character, will produce a different message after decryption. When the receiver re-hashes that altered message, the result will not match the hash that arrived with it. The system catches the tampering.

---

## Sample output

Running option 1 with message `HELLOCRYPTOGRAPHY` and key `5`:

```
  [Sender] Message         : HELLOCRYPTOGRAPHY
  [Sender] Hash H(M)       : 765595EB
  [Sender] Payload M||H(M) : HELLOCRYPTOGRAPHY765595EB
  [Sender] Ciphertext      : HCOH5ERGY9LYR75LPA6EOTP5B
  [Sender] Matrix shape    : 5 rows x 5 cols

  [Receiver] Decrypted payload : HELLOCRYPTOGRAPHY765595EB
  [Receiver] Recovered message : HELLOCRYPTOGRAPHY
  [Receiver] Received hash     : 765595EB
  [Receiver] Computed hash     : 765595EB
  [Receiver] Auth result       : AUTHENTIC -- message is unmodified
```

Running the same test with tampering enabled (first byte of ciphertext is flipped):

```
  [Receiver] Decrypted payload : ZECRETMESSAGE2D8F20E9
  [Receiver] Recovered message : ZECRETMESSAGE
  [Receiver] Received hash     : 2D8F20E9
  [Receiver] Computed hash     : 95059861
  [Receiver] Auth result       : TAMPERED -- hash mismatch, message rejected
```

---

## Complexity

| Operation | Time | Space |
|---|---|---|
| Route Cipher encrypt | O(n) | O(n) |
| Route Cipher decrypt | O(n) | O(n) |
| Custom hash | O(n) | O(n) |
| Full pipeline | O(n) | O(n) |

`n` is the length of the message. All operations scale linearly because each character or byte is processed a fixed number of times.

---

## Design decisions summarised

| Decision | Why |
|---|---|
| Columnar route (not spiral or zigzag) | Simpler to implement and reverse, works for any matrix size |
| Pad with `X` | A fixed, visible character makes it easy to strip cleanly |
| Key = number of columns | One shared integer is enough to encrypt and decrypt |
| 4-byte block hash | Keeps the hash simple while still processing the full message |
| Append hash to message before encrypting | Both confidentiality and integrity are covered in one pass |
| No external libraries | Required by the assignment; builds understanding from the ground up |

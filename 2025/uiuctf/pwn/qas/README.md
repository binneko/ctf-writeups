# QAS

## Challenge Summary

- **Category**: Pwn
- **Points**: 50
- **Solves**: 212 teams

---

### Problem Description

> Since we are so behind on adopting "AI", corporate has decided to pivot to "quantum". They mandated we "quantumfy" our tech stack. Please review our latest authentication protocol.

---

## Challenge Structure

- The challenge is a 64-bit ELF binary that takes user input, stores it in a struct field, computes a hash, and checks whether it matches a fixed value (`0x555`) to determine if authentication is successful.
- The input is read using `scanf("%d", ...)`, which reads a 4-byte integer. However, the struct field where the input is stored is only 2 bytes wide.
- As a result, the remaining 2 bytes of the input overwrite the adjacent fields `padding[0]` and `padding[1]` within the struct. These overwritten bytes are later used in the hash calculation, creating a vulnerability that allows an attacker to influence the final result.

---

## Exploitation Flow

### Step 1: Understanding Input Overwrite in the Struct

The relevant struct and input code are defined as follows:

```c
typedef struct {
    int_small val;             // Actually a short → 2 bytes
    quantum_byte padding[2];   // Two 1-byte values
    quantum_byte checksum;
    quantum_byte reserved;
} INPUT_QUANTUM;

...

scanf("%d", (int*)&qdata.input.val);
```

* `val` is 2 bytes in size, but `scanf("%d", ...)` reads a full 4-byte integer.
* Due to the explicit cast to `(int*)`, the input ends up overwriting not just `val`, but also `padding[0]` and `padding[1]`.
* These padding values are later used in the final stage of the hash function and can be manipulated to affect the result.

---

### Step 2: Authentication Condition and Hash Logic

The program checks the authentication condition using:

```c
if (hashed_input == qdata.password.val) {
    access_granted();
}
```

The password value is hardcoded at runtime:

```c
qdata.password.val = 0x555;
```

Thus, the goal is to craft an input such that the result of the hash function equals `0x555`.

The hash function is as follows:

```c
hash = input.val;
hash ^= (entropy[0] << 8) | entropy[1];
hash ^= (entropy[2] << 4) | (entropy[3] >> 4);
hash += (entropy[4] * entropy[5]) & 0xff;
hash ^= entropy[6] ^ entropy[7];
hash |= 0xeee;
hash ^= padding[0] << 8 | padding[1];
```

* The `|= 0xeee` step forces the lower bits to be set, making it nearly impossible to obtain a value like `0x555` under normal conditions.
* However, since the padding values can be overwritten via the input, the final XOR operation can cancel out the forced bits and make the final hash match `0x555`.

---

### Step 3: Finding the Bypass Input

The task is to find a specific 4-byte input that, when written into `val`, `padding[0]`, and `padding[1]`, results in a hash of `0x555`.

Using brute-force or symbolic analysis, the correct input was found to be:

```
-1433792511 → quantum_hash(...) == 0x555
```

This value overwrites all three relevant fields in the struct and results in a valid hash.

---

### Step 4: Exploit Execution

> The exploit code is provided in an attached file.
> After receiving the `code:` prompt, entering `-1433792511` bypasses the authentication check and calls `access_granted()`, which prints the flag.

---

## Flag

```
CLASSIFIED FLAG: uiuctf{qu4ntum_0v3rfl0w_2d5ad975653b8f29}
```

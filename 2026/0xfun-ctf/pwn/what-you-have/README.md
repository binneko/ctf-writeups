# What you have

## 1. Summary

- **Category**: Pwnable
- **Points**: 100
- **Solves**: 430

### Description

> `Bring it on! Show me EVERYTHING you’ve got! I want to see all you've got!`

## 2. Analysis

### Checksec

```text
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

### Vulnerability

- **Arbitrary Address Write**: The `main` function takes two unsigned long integers as input via `scanf`. The first input is treated as a pointer (`local_20`), and the second input is the value (`local_18`) to be written at that address.
- **No RELRO**: Since the binary has "No RELRO", the GOT is writable. This is a critical weakness that allows us to redirect program execution by overwriting the entry of a library function.

```c
  __isoc99_scanf("%lu",&local_20); // Get target address
  puts("Show me what you GOT! I want to see what you GOT!");
  __isoc99_scanf("%lu",&local_18); // Get value to write
  *local_20 = local_18;           // Arbitrary Write
```

- **Hidden Win Function**: There is a `win` function present in the binary that reads and prints the flag. Although it is not called anywhere in the normal execution flow, its existence provides a clear target for our arbitrary write.

## 3. Exploit Flow

1. **Target Identification**
   After the arbitrary write occurs (`*local_20 = local_18`), the program calls `puts("Goodbye!");`. By overwriting the GOT entry of `puts` with the address of the `win` function, the call to `puts` will actually execute `win`.

2. **Calculating Addresses**
   Since PIE is disabled, the addresses of `elf.got.puts` and `elf.sym.win` are static and can be easily identified.

3. **Execution**
   - Provide the address of `puts@GOT` when prompted for the first value.
   - Provide the address of the `win` function when prompted for the second value.
   - When the program attempts to call `puts("Goodbye!")`, it redirects to `win`, which opens `flag.txt` and prints the flag.

## 4. Final Solution

- **Exploit Code**: [Link to Script / GitHub](./solve.py)

```python
    # Overwrite puts@GOT with win()
    r.sendlineafter(b"!\n", f"{elf.got.puts}".encode())
    r.sendlineafter(b"!\n", f"{elf.sym.win}".encode())
```

## 5. Flag

`0xfun{g3tt1ng_schw1fty_w1th_g0t_0v3rwr1t3s_1384311_m4x1m4l}`

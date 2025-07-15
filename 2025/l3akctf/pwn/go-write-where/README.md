[*] '/ctf-writeups/2025/l3akctf/pwn/go-write-where/dist/chall'
# Go Write Where

## Challenge Summary

- **Category**: Pwn  
- **Points**: 392  
- **Solves**: 50 teams  

---

### Problem Description

> Go get shell with a new arbitrary read/write feature.

---

## Challenge Structure

- The binary provides a one-time arbitrary read/write feature.
- However, by exploiting a local loop counter, this restriction can be bypassed, enabling multiple memory operations.

---

### Protections

```
Arch:       amd64-64-little
RELRO:      No RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
Debuginfo:  Yes
```

---

## Exploitation Flow

### Step 1: Bypassing Loop Limitation

The vulnerable code:
```c
for (lVar1 = 1; 0 < lVar1; lVar1--) {
    // Read/Write logic here
}
```

- The read/write loop runs only once by default.
- The loop counter `lVar1` is stored on the stack, at a runtime-determined address (due to ASLR).
- By brute-forcing the loop variable’s memory address and overwriting it with 0xff, it’s possible to run the loop multiple times, effectively lifting the one-time restriction.
- This allows arbitrary read/write interactions repeatedly:
  
```text
Read or Write? (r/w):
```

### Step 2: Writing /bin/sh

- The string "/bin/sh" is written to the `.bss` section.

### Step 3: Building ROP Chain

- Since PIE is disabled, fixed addresses for gadgets can be used.
- The following ROP chain is built to perform `execve("/bin/sh", NULL, NULL)`:

```asm
pop rdi     ; set rdi to /bin/sh
pop rax     ; rax = 0
mov rsi, rax
pop rdx     ; rdx = 0
pop rax     ; rax = 59 (sys_execve)
syscall
```

- ROP chain is written to a known memory address (`0xc00009cf48`) using the write primitive.

### Step 4: Triggering the ROP

- After the ROP chain is written into memory, the loop counter is set back to `1` so that the loop completes, allowing the program to return and execute the crafted ROP chain.
- The ROP chain spawns a shell, allowing us to read the flag.

---

## Flag

```bash
$ cat flag.txt
L3AK{60_574ck_15_4lm057_pr3d1c74bl3}
```

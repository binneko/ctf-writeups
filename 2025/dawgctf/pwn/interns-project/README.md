# Interns'Project

## 🧩 Challenge Summary

- **Category**: Pwn
- **Points**: 100
- **Solves**: 238 teams

---

### 📝 Problem Description

> Our interns put together a little test program for us.\
> It seems they all might have patched together their separate projects.\
> Could you test it out for me?

---

## 🧠 Vulnerability Analysis

Key vulnerability lies in the fact that **only the first option is checked** for privileged execution,
while all options are later executed unconditionally. The decompiled snippet below shows the relevant logic:

```cpp
if (v14[0] == 2 && geteuid()) {
    std::cout << "Error: Option 2 requires root privileges HAHA" << std::endl;
} else {
    for (i = 0; i < v10; ++i) {
        switch (v14[i])
        {
            case 1:
                sayHello();
                break;
            case 2:
                printFlag();
                break;
            case 3:
                login();
                break;
        }
    }
}
```

---

## ✅ Exploit Strategy

Option `2` (printFlag) is meant to be protected behind a root check. But since the check only applies to the first value,
**placing `2` later in the input list bypasses the restriction.**

### 🤕 Example:

```
Input: 1 2
```
- `1` passes the check
- `2` is later executed, triggering `printFlag()`

---

## 💻 Steps to Reproduce

```bash
Welcome to our intern's test project!

The following are your options:
   1. Say hi
   2. Print the flag
   3. Create an account
Enter option (1-3). Press Enter to submit:
1 2
Hi!
Here is your flag: DawgCTF{B@d_P3rm1ssi0ns}
```

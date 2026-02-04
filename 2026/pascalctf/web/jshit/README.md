# JSHit

## 1. Summary

- **Category**: Web / Misc
- **Points**: 50
- **Solves**: 630

### Description

> `I hate Javascript sooo much, maybe I'll write a website in PHP next time🔥!`

## 2. Analysis

### Vulnerability

- **Code Obfuscation (JSFuck)**: The challenge relies on **JSFuck** obfuscation to hide its logic. While it looks complex, it is simply a series of unconventional JavaScript expressions that the browser executes as plain code. The sensitive logic—including the flag string—is exposed once the script is evaluated in the browser's memory.

## 3. Exploit Flow

1. **Initial Inspection**: Accessing the site reveals a massive block of JSFuck code within a `<script>` tag.
2. **Console Debugging**: Checking the browser's Developer Tools (F12) reveals a log: `where's the page gone?`.
3. **Trace Evaluation**: By clicking the source link in the console (e.g., `eval:1:426`), the browser de-obfuscates and displays the original source code.
4. **Flag Retrieval**: The source code contains a ternary operator comparing the `flag` cookie with a hardcoded string. The flag is found directly in that comparison logic.

## 4. Final Solution

- **Exploit Code**: Not required. The flag is statically embedded within the obfuscated script's logic.

## 5. Flag

`pascalCTF{1_h4t3_j4v4scr1pt_s0o0o0o0_much}`

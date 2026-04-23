# Temporary Destruction

## 1. Summary

- **Category**: Web
- **Points**: 673
- **Solves**: 325

### Description

> `I hear something....`

## 2. Analysis

### Vulnerability

- **SSTI (Server-Side Template Injection)**: The application uses the `render_template_string()` function to process user-supplied input. While there is a regex filter `__\w+__` to block access to internal Python attributes (like `__globals__` or `__class__`), it can be bypassed using hex-encoded strings within dictionary-style access.

## 3. Exploit Flow

1. **Bypassing the Regex Filter**
   The filter searches for literal double underscores. We can bypass this by using hex escape sequences (e.g., `\x5f\x5f`) inside square brackets.

2. **Remote Code Execution (RCE)**
   By accessing the `lipsum` object—a built-in helper in Jinja2—we can navigate to the `os` module through `globals` and execute system commands via `popen`.

   **Payload Structure:**

   ```jinja2
   {{ lipsum['\x5f\x5fglobals\x5f\x5f']['os']['popen']('cat /tmp/flag.txt')['read']() }}
   ```

## 4. Final Solution

- **Exploit Payload**:
  `{{ lipsum['\x5f\x5fglobals\x5f\x5f']['os']['popen']('cat /tmp/flag.txt')['read']() }}`

## 5. Flag

`CIT{55T1_R3m0t3_C0d3_3x3cut1on}`

# Templates

## 1. Summary

- **Category**: Web
- **Points**: 1
- **Solves**: 786

### Description

> `Just a simple service made using Server Side Rendering.`

## 2. Analysis

### Vulnerability

- **Server-Side Template Injection (SSTI)**: The application provides a "Greeting Service" where users can enter their name. The input is then reflected back on the page.
- **Insecure Rendering**: Because the service uses Server-Side Rendering (SSR) and reflects user input directly into the template engine without sanitization, it is vulnerable to template injection.
- **Identification**: By submitting the payload `{{ 7 * 7 }}`, the server rendered the result `49`. This confirms that the input is being evaluated as an expression by a template engine (likely Jinja2 or Mako, common in Python environments).

## 3. Exploit Flow

1. **Discovery**
   Initial testing with simple mathematical expressions showed that the template engine evaluates code enclosed in double curly braces.

2. **Sandbox Escape & Payload Crafting**
   To execute system commands, it is necessary to traverse the Python object hierarchy to access the `os` module. The following path was used:
   - `self.__init__`: Accesses the initialization function of the current object.
   - `.__globals__`: Accesses the global dictionary of the function.
   - `.__builtins__`: Accesses built-in functions, including `__import__`.
   - `.__import__('os')`: Imports the OS module for interaction with the operating system.
   - `.popen('cat flag.txt').read()`: Executes the shell command to read the flag file.

3. **Execution**
   The full payload was sent through the name input field:
   `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat flag.txt').read() }}`

## 4. Final Solution

- **Exploit Payload**:
  `{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat flag.txt').read() }}`

## 5. Flag

`0xfun{Server_Side_Template_Injection_Awesome}`

# mutation mutation

## 1. Summary

- **Category**: Web
- **Points**: 100
- **Solves**: 621

### Description

> `It's a free flag! You just gotta inspect the page to get it. Just be quick though... the flag is constantly mutating. Can you catch it before it changes? 🧬`

## 2. Analysis

### Vulnerability

- **DOM Mutation**: When accessing the site, the message "Free flag! All you need to do is inspect this page!" is displayed. Checking the `Inspector` reveals dozens of comment nodes in the format `<!--lactf{...}-->`. These nodes are created and deleted dozens of times every second (Mutation), making it extremely difficult to identify the real flag with the naked eye.

## 3. Exploit Flow

1. **Capturing a DOM Snapshot**
   To freeze the rapidly changing DOM nodes, right-click the top-level `<!DOCTYPE html>` node in the `Inspector` window and select **`Use in Console`**. This assigns the state of the nodes at that specific moment to the variable `temp0`.

2. **Exploring Child Nodes via Console**
   Enter the command `temp0.ownerDocument.childNodes` in the console to view all child elements (including comments) captured in the snapshot as a list.

3. **Identifying the Real Flag**
   Among the numerous fake flags (`fake`, `honeypot`, `almost`, etc.) in the output `NodeList`, locate the real flag which features a unique and complex string format.

```javascript
// Console input and example output
>> temp0.ownerDocument.childNodes
NodeList(40) [ <!DOCTYPE html>, <!-- lactf{decoy}... -->, ... ]
// ... omission ...
59: <!--  lactf{с0nѕtаnt_mutаtі0n_1s_fun!_🧬_👋🏽_ІlІ1| ض픋ԡೇ∑ᦞ୞땾᥉༂↗ۑீ᤼യ⌃±❣Ӣ◼ௌௌௌௌௌௌ...}  -->
```

## 4. Final Solution

- **Exploit Method**: Used the browser developer tools console to dump the mutating DOM nodes into a static state for analysis.

## 5. Flag

`lactf{с0nѕtаnt_mutаtі0n_1s_fun!_🧬_👋🏽_ІlІ1| ض픋ԡೇ∑ᦞ୞땾᥉༂↗ۑீ᤼യ⌃±❣Ӣ◼ௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌௌ}`

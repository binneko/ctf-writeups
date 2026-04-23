# Intern Portal

## 1. Summary

- **Category**: Web
- **Points**: 752
- **Solves**: 246

### Description

> `The intern said they made a custom report application... but I don't think security was in mind.`

## 2. Analysis

### Vulnerability

- **Insecure Direct Object Reference (IDOR)**: The application does not perform proper authorization checks when accessing reports via the `id` parameter. This allows any authenticated user to view reports created by others by simply manipulating the ID in the URL.

## 3. Exploit Flow

1. **Identify Report Access Pattern**
   After submitting a report, the application redirects to a URL like `http://23.179.17.92:5001/report?id=[ID]`. The content is fetched based solely on the numeric `id`.

2. **ID Enumeration**
   By changing the `id` value in the query string (e.g., `id=1`), it was confirmed that reports belonging to other users were visible.

3. **Flag Discovery**
   By enumerating or searching for specific report IDs, the flag was discovered in report #347.

## 4. Final Solution

- **Exploit Code**: [Link to Script / GitHub](./solve.py)

## 5. Flag

`CIT{Acc355_C0ntr0l_M@tt3rs!}`

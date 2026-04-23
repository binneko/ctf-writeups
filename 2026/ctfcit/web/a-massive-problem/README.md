# A Massive Problem

## 1. Summary

- **Category**: Web
- **Points**: 581
- **Solves**: 417

### Description

> `Improper Authorization has been fixed! I think we are ready for production!`

## 2. Analysis

### Vulnerability

- **Mass Assignment (Insecure Parameter Binding)**: The application logic in the `/api/profile` endpoint uses a dictionary `update()` method on the user record with unfiltered user input (`incoming`). This allows an attacker to overwrite sensitive fields—specifically the `role` field—which should not be modifiable by a standard user.

## 3. Exploit Flow

1. **Identifying the Weakness**
   In the `update_profile` function, the code fetches the current user's record and then performs a bulk update using `record.update(incoming)`. Since `incoming` is derived directly from the JSON or form data provided by the user, we can include a `"role": "admin"` key-value pair in our request.

2. **Privilege Escalation via Profile Update**
   By sending a POST request to `/api/profile` with the payload `{"role": "admin"}`, the application updates the database record for the current user, changing their status from `standard` to `admin`.

3. **Accessing the Flag**
   After the update, the user re-authenticates to refresh the session state. Since the `role` is now `admin`, the `/admin` endpoint passes the authorization check and returns the flag.

```python
# Key logic in update_profile
record = {
    'username': current['username'],
    'password': current['password'],
    'role': current['role'], # Current role
    ...
}
record.update(incoming) # Vulnerable: Updates 'role' if present in input
```

## 4. Final Solution

- **Exploit Code**: [Link to Script / GitHub](./solve.py)

## 5. Flag

`CIT{M@ss_@ssignm3nt_Pr1v3sc}`

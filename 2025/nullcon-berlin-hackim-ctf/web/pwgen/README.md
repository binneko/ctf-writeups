# pwgen

## Challenge Summary

- **Category**: Web
- **Points**: 100
- **Solves**: 220 teams

---

### Problem Description

> Password policies aren't always great. That's why we generate passwords for our users based on a strong master password!

---

## Challenge Structure

- The service takes an `nthpw` parameter and outputs the flag (`$FLAG`) after applying `str_shuffle()`.
- Since the random seed is fixed with `srand(0x1337)`, the shuffle is deterministic.
- By analyzing the shuffled output, it’s possible to recover the original flag.

---

## Exploitation Flow

### Step 1: Source Code Review

- From `/?source`, the critical logic is:

```php
srand(0x1337);
for($i = 0; $i < $shuffle_count; $i++) {
    $password = str_shuffle($FLAG);
}
```

- The shuffle always produces the same output, and with `nthpw=1`, we get a single shuffled flag.

### Step 2: Shuffle Tracking

- Insert a marker (`\\x01`) into a dummy string.
- Run `str_shuffle()` with the fixed seed to see where the marker ends up.
- Repeat this process to build the mapping from **original index → shuffled index**.

### Step 3: Flag Recovery

- Use the mapping to reconstruct the original flag from the shuffled output.
- Recovery script:

```php
$DUMMY = str_repeat(" ", 129);
$FLAG = "";
$SHUFFLED_PW = "7F6_23Ha8:5E4N3_/e27833D4S5cNaT_1i_O46STLf3r-4AH6133bdTO5p419U0n53Rdc80F4_Lb6_65BSeWb38f86{dGTf4}eE8__SW4Dp86_4f1VNH8H_C10e7L62154";

for ($i = 0; $i < 130; $i++) {
    srand(0x1337);
    $dummy = substr_replace($DUMMY, "\\x01", $i, 0);
    $password = str_shuffle($dummy);
    $marker_pos = strpos($password, "\\x01");
    $FLAG .= $SHUFFLED_PW[$marker_pos];
}

echo "$FLAG\\n";
```

---

## Flag

```
ENO{N3V3r_SHUFFLE_W1TH_STAT1C_S333D_OR_B4D_TH1NGS_WiLL_H4pp3n:-/_0d68ea85d88ba14eb6238776845542cf6fe560936f128404e8c14bd5544636f7}
```

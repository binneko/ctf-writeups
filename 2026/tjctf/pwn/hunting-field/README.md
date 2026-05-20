# hunting-field

## 1. Summary

- **Category**: Pwn
- **Points**: 329
- **Solves**: 202

### Description

> `Take up your arms, and slay your enemies!`

## 2. Analysis

### Checksec

```text
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```

### Vulnerability

The challenge is a small game where the player moves around a map and defeats enemies to gain points.

```text
0
. . . . . . . . .
. . . . . . . . .
. . . . . . . . .
. . . . . . . . .
. . . . @ . . . .
. . . . . . . . .
. . . . . . . . .
. . . . . . . . .
. . . . . . . . . Enter (M)ove or (A)ttack, followed by direction (N)orth (E)ast (S)outh (W)est
```

The flag is printed only if the player's kill count matches a specific value:

```c
void game_over(int *kills)
{
    puts("\nGame Over!");
    printf("You defeated %i enemies!\n", *kills);

    if (*kills == 1752526452)
    {
        int flagSize = 30;
        char flag[flagSize];
        FILE* file_ptr;

        file_ptr = fopen("./flag.txt", "r");

        if (file_ptr == NULL)
        {
            printf("Failed to get flag. Make sure you have a file titled flag.txt somewhere in this directory!");
        }
        else if(fgets(flag, flagSize, file_ptr) != NULL)
        {
            printf("So many foes have fallen before you. Take this flag as proof of your victory!\n %s \n", flag);
        }
    }
}
```

The `kills` argument points to the local variable `killCt`:

```c
int killCt = 0;
int *kills = &killCt;
```

From the decompiled code:

```c
uint *local_40;
...
local_40 = local_8c;
```

we can identify `local_8c` as the storage for `killCt`.

The vulnerability exists in the input logging logic:

```c
char player_input[2] = "Hi";

while ((!strchr("MA", player_input[0])) ||
       (!strchr("NESW", player_input[1])))
{
    printf("Enter (M)ove or (A)ttack, followed by direction (N)orth (E)ast (S)outh (W)est ");

    scanf("%c", &player_input[0]);
    scanf("%c", &player_input[1]);

    int c;
    while ((c = getchar()) != '\n' && c != EOF);

    *array_ptr = player_input[0];
    array_ptr -= sizeof(player_input[0]);

    *array_ptr = player_input[1];
    array_ptr -= sizeof(player_input[1]);
}
```

Invalid input causes the loop to repeat indefinitely. Each iteration decrements `array_ptr` by 2, allowing an out-of-bounds write into adjacent stack variables.

```c
char input_log[64];
char *array_ptr = &input_log[63];
```

In the decompiled output:

```c
local_18 = &local_49;
```

`local_49` corresponds to `input_log[63]`, while `killCt` is stored at `local_8c`.

The distance between them is `0x40` bytes, so sending invalid input `0x20` times moves the pointer directly onto `killCt`.

## 3. Exploit Flow

1. **Reach `killCt` Using Invalid Inputs**

   ```python
   for _ in range(0x20):
       r.sendlineafter(b"(W)est ", b"XX")
   ```

   Each invalid input decreases the write pointer by 2 bytes.

1. **Overwrite `killCt`**

   The required value is:

   ```text
   1752526452 = 0x68756e74
   ```

   Interpreted as ASCII, this becomes:

   ```text
   hunt
   ```

   Since the bytes are written in reverse order due to the pointer movement, the payload must be sent in big-endian order:

   ```python
   r.sendlineafter(b"(W)est ", b"hu")
   r.sendlineafter(b"(W)est ", b"nt")
   ```

   However, there is an additional issue:

   ```c
   array_ptr += 2*sizeof(player_input[0]);
   ```

   After the validation loop exits, the pointer is incremented by 2, causing subsequent writes to overwrite `killCt` again.

   To avoid corrupting the value, one additional invalid input is sent so that the final adjustment lands on `player_input` instead of `killCt`.

1. **Trigger `game_over()`**

   The game ends when the player moves onto an enemy tile:

   ```c
   if (map[player_position] == 'E') {
       game_over(kills);
       break;
   }
   ```

   Enemies spawn according to the following logic:

   ```c
   if (turn_cnt % 2 == 0 || turn_cnt % 5 == 0)
   {
       int rando =
           (turn_cnt * player_input[0] * player_input[1]
           + player_position) % 18;

       if (rando > 8)
           rando += 63;

       if (map[rando] == '.')
           map[rando] = 'E';
   }
   ```

   Since `turn_cnt` starts at 1, the first enemy spawns after the second move.

   The following movement sequence reliably triggers an encounter:

   ```python
   for cmd in [b"MN", b"MW", b"MN", b"MW", b"MW"]:
       r.sendlineafter(b"(W)est ", cmd)
   ```

## 4. Final Solution

- **Exploit Code**: [Link to Script / GitHub](./solve.py)

## 5. Flag

`tjctf{pr0fes5iona1_hunt3r}`

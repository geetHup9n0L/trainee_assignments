### Thông tin file:

```c
└─$ ls
chall  Dockerfile
```
```c
└─$ file chall 
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=df3e70e986fcc294430e2e416a9343018e40b118, for GNU/Linux 4.4.0, not stripped
```
```c
└─$ checksec --file=chall 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   34 Symbols  No     0               3               chall
```
___
Code:

`main()`:
```c
undefined8 main(void)

{
  FILE *buffer;
  long in_FS_OFFSET;
  undefined1 flag [32];
  undefined1 ptr [264];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  setbuf(stdin,(char *)0x0);
  setbuf(stdout,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  printf("my aura: %p\nur aura? ",&aura);
  buffer = fopen("/dev/null","r");
  read(0,buffer,256);
  fread(ptr,1,8,buffer);
  if (aura == 0) {
    puts("u have no aura.");
  }
  else {
    buffer = fopen("flag.txt","r");
    fread(flag,1,0x11,buffer);
    printf("%s\n ",flag);
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}

```
* DÒng này làm gì
  ```c
    buffer = fopen("/dev/null","r");
    read(0,buffer,256);
    fread(ptr,1,8,buffer);
  ```

* biến global `aura`
  ```c
    if (aura == 0) {
      puts("u have no aura.");
    }
  ```
  <img width="499" height="86" alt="image" src="https://github.com/user-attachments/assets/c9c41497-b894-4650-967b-f42595e5c780" />

* bên cạnh đấy, khi học đến cấu trúc FILE, giờ ta mới để ý đến:
  ```c
  setbuf(stdin,(char *)0x0);
  setbuf(stdout,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  ```
  `stdin`, `stdout`, `stderr` cũng là các biến global 

  <img width="531" height="570" alt="image" src="https://github.com/user-attachments/assets/0b58c9ac-3e44-441d-aa26-594ec60c565c" />


___
### Exploit:



___
reference:

https://www.youtube.com/watch?v=Tv1Rss5Vqpk&t=490s

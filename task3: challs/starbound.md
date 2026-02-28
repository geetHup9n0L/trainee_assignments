Thông tin file:

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
Code từ ghidra:

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
















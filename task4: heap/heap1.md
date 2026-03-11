### Thông tin file:

```c
└─$ file pwn1_ff 
pwn1_ff: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-2.23.so, for GNU/Linux 2.6.32, BuildID[sha1]=b744398ed054457775b2ede2fc6f427f294fca56, stripped
```
```c
└─$ checksec --file=pwn1_ff  
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   No Symbols  No     0               2               pwn1_ff
```
* `Partial RELRO`: overwrite GOT
* `No PIE`: địa chỉ binary tĩnh

Chương trinh đang thiếu loader, nên ta dùng patchelf:
```bash
└─$ patchelf --set-interpreter /lib64/ld-linux-x86-64.so.2 pwn1_ff_copy
```

Output chương trình:

<img width="810" height="145" alt="image" src="https://github.com/user-attachments/assets/82bbb14c-712d-4920-b5aa-cd8f89d94834" />

Code từ ghidra (với các biến được đặt tên lại):
* `main()`:
```c
void main(void)
{
  int choice;
  
  init();
  puts("Ez heap challange !");
  do {
    while( true ) {
      while( true ) {
        menu();
        choice = read_input();
                    /* 1-create;2-delete;3-exit */
        if (choice != 2) break;
        delete();
      }
      if (2 < choice) break;
      if (choice == 1) {
        create();
      }
      else {
LAB_00400d2a:
        puts("no option");
      }
    }
    if (choice == 3) {
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    if (choice != 4) goto LAB_00400d2a;
    flag_check();
  } while( true );
}
```
`create()`:
```c
undefined8 create(void)
{
  uint size;
  data *data;
  char *content;
  int i;
  
  for (i = 0; (i < 9 && ((&database)[i] != (data *)0x0)); i = i + 1) {
  }
  printf("Input size:");
  size = read_input();
  if (size < 4097) {
    data = (data *)malloc(0x10);
    content = (char *)malloc((ulong)size);
    data->content = content;
    (&database)[i] = data;
    printf("Input data:");
    read(data->content,size);
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```
* có `database` (là `DAT_006020e0` lúc trước) là vùng nhớ trên heap, chứa các pointer `data` từ 0 đến 8
* có `data` là vùng nhớ được cấp phát động để chứa pointer trỏ đến chunk của `content` cũng được cấp phát động theo `size` do người dùng đặt
* có `size` tối đa = `4096`, có thể tận dụng cho **heap overflow**
`delete()`:
```c
undefined8 delete(void)
{
  int index;
  undefined *ptr;
  
  printf("Input index:");
  index = read_input();
  if ((index < 10) && (-1 < index)) {
    if ((&database)[index] != (data *)0x0) {
      ptr = (&database)[index]->content;
      free((&database)[index]);
      free(ptr);
      (&database)[index]->content = (undefined *)0x0;
      (&database)[index] = (data *)0x0;
      puts("Done ");
    }
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```
`flag_check()`:
```c
undefined8 flag_check(void)

{
  if ((DAT_006020f0 != 0) && (*(long *)(DAT_006020f0 + 8) == 0xabcdef)) {
    get_flag();
  }
  return 0;
}
```

<img width="695" height="447" alt="image" src="https://github.com/user-attachments/assets/4b9b37f5-5382-40d6-9b99-f3e132183f2c" />

___







___
doc:

https://www.youtube.com/watch?v=aU1_PXlMBhg
















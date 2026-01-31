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

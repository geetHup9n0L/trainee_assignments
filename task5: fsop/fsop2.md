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
      store = ptr;
    }
    else {
      for (store_idx = store; store_idx[2] != 0; store_idx = (long *)store_idx[2]) {
      }
      store_idx[2] = (long)ptr;
      puts("Done");
    }
  }
  return;
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

___
### Exploit:


___
`script.py`:
```python

```


___




```

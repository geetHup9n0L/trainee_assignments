### Thông tin file:
```c
└─$ ls
libc.2.23.so  pwn2_df
```
```c
└─$ file pwn2_df 
pwn2_df: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-2.23.so, for GNU/Linux 3.2.0, BuildID[sha1]=448d3beedfd5ae424f8d857ba8b2e06eb7e09591, not stripped
```
```c
└─$ checksec --file=pwn2_df 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   85 Symbols  No     0               2               pwn2_df
```

heap1

___
Code của chương trình:
`main()`:
```c
void main(void)
{
  undefined4 option;
  
  initState();
  puts("Ez heap challange !");
  do {
    menu();
    option = readInt();
    switch(option) {
    default:
      puts("no option");
      break;
    case 1:
      createHeap();
      break;
    case 2:
      showHeap();
      break;
    case 3:
      editHeap();
      break;
    case 4:
      deleteHeap(0);
      break;
    case 5:
      exit(0);
    }
  } while( true );
}
```
`createHeap()`:
```c
undefined8 createHeap(void)
{
  int idx;
  uint size;
  char **ptr;
  
  printf("Index:");
  idx = readInt();
  if ((-1 < idx) && (idx < 10)) {
    printf("Input size:");
    size = readInt();
    if (4096 < size) {
      exit(0);
    }
    ptr = (char **)malloc((ulong)size);
    (&store)[idx] = ptr;
    (&storeSize)[idx] = size;
    printf("Input data:");
    readStr((&store)[idx],size);
    puts("Done");
    return 0;
  }
  exit(0);
}
```
`showHeap()`:
```c
undefined8 showHeap(void)
{
  int idx;
  
  printf("Index:");
  idx = readInt();
  if ((-1 < idx) && (idx < 10)) {
    if ((&store)[idx] != (char **)0x0) {
      printf("Data = %s\n",(&store)[idx]);
    }
    return 0;
  }
  exit(0);
}
```
`editHeap()`:
```c
undefined8 editHeap(void)
{
  int idx;
  
  printf("Input index:");
  idx = readInt();
  if ((idx < 10) && (-1 < idx)) {
    if ((&store)[idx] != (char **)0x0) {
      readStr((&store)[idx],(&storeSize)[idx]);
      puts("Done ");
    }
    return 0;
  }
  exit(0);
}
```
`deleteHeap()`:
```c
undefined8 deleteHeap(void)
{
  int idx;
  
  printf("Input index:");
  idx = readInt();
  if ((idx < 10) && (-1 < idx)) {
    if ((&store)[idx] != (char **)0x0) {
      free((&store)[idx]);
      puts("Done ");
    }
    return 0;
  }
  exit(0);
}
```


___
### Exploit:

___
`script.py`:
```python

```
___

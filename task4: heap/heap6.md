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
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
  } while( true );
}


undefined8 createHeap(void)

{
  int idx;
  void *ptr;
  
  printf("Index:");
  idx = readInt();
  if ((-1 < idx) && (idx < 10)) {
    ptr = malloc(0x80);
    *(void **)(store + (long)idx * 8) = ptr;
    *(undefined4 *)(storeSize + (long)idx * 4) = 0x80;
    printf("Input data:");
    readStr(*(undefined8 *)(store + (long)idx * 8),0x80);
    puts("Done");
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  exit(0);
}


ulong readStr(void *buffer,uint size)

{
  int len;
  ulong bytes;
  
  bytes = read(0,buffer,(ulong)size);
  len = (int)bytes;
  if (len < 0) {
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  if (*(char *)((long)buffer + (long)len + -1) == '\n') {
    *(undefined1 *)((long)buffer + (long)len + -1) = 0;
  }
  return bytes & 0xffffffff;
}


undefined8 showHeap(void)

{
  int idx;
  
  printf("Index:");
  idx = readInt();
  if (*(long *)(store + (long)idx * 8) != 0) {
    printf("Data = %s\n",*(undefined8 *)(store + (long)idx * 8));
  }
  return 0;
}


undefined8 editHeap(void)

{
  int idx;
  
  printf("Input index:");
  idx = readInt();
  if ((idx < 10) && (-1 < idx)) {
    if (*(long *)(store + (long)idx * 8) != 0) {
      readStr(*(undefined8 *)(store + (long)idx * 8),*(undefined4 *)(storeSize + (long)idx * 4));
      puts("Done ");
    }
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  exit(0);
}


undefined8 deleteHeap(void)

{
  int idx;
  
  printf("Input index:");
  idx = readInt();
  if ((idx < 10) && (-1 < idx)) {
    if (*(long *)(store + (long)idx * 8) != 0) {
      free(*(void **)(store + (long)idx * 8));
      puts("Done ");
    }
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  exit(0);
}


```

![image](images/heap6/img1.png)

File: `crossbow`
```c
┌──(kali㉿kali)-[~/training_PWN/pwn_crossbow/challenge]
└─$ checksec --file=crossbow 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   241 Symbols  No    0               0               crossbow
```
Assembly code: `crossbow`
```c
undefined8 main(void)
{
  setvbuf((FILE *)__stdin_FILE,(char *)0x0,2,0);
  setvbuf((FILE *)__stdout_FILE,(char *)0x0,2,0);
  alarm(4882);
  banner();
  training();
  return 0;
}


void training(void)
{
  undefined1 buffer [32];
  
  printf("%s\n[%sSir Alaric%s]: You only have 1 shot, don\'t miss!!\n",&DAT_0040b4a8,&DAT_0040b00e,
         &DAT_0040b4a8);
  target_dummy(buffer);
  printf("%s\n[%sSir Alaric%s]: That was quite a shot!!\n\n",&DAT_0040b4a8,&DAT_0040b00e,
         &DAT_0040b4a8);
  return;
}


void target_dummy(long buffer)
{
  int choice;
  void *memory;
  char *fg;
  int input [3];
  long *buffer_ptr;
  
  printf("%s\n[%sSir Alaric%s]: Select target to shoot: ",&DAT_0040b4a8,&DAT_0040b00e,&DAT_0040b4a8)
  ;
  choice = scanf("%d%*c",input);
  if (choice != 1) {
    printf("%s\n[%sSir Alaric%s]: Are you aiming for the birds or the target kid?!\n\n",
           &DAT_0040b4e4,&DAT_0040b00e,&DAT_0040b4e4);
                    /* WARNING: Subroutine does not return */
    exit(1312);
  }
  buffer_ptr = (long *)((long)input[0] * 8 + buffer);
  memory = calloc(1,128);
  *buffer_ptr = (long)memory;
  if (*buffer_ptr == 0) {
    printf("%s\n[%sSir Alaric%s]: We do not want cowards here!!\n\n",&DAT_0040b4e4,&DAT_0040b00e,
           &DAT_0040b4e4);
                    /* WARNING: Subroutine does not return */
    exit(0x1b39);
  }
  printf("%s\n[%sSir Alaric%s]: Give me your best warcry!!\n\n> ",&DAT_0040b4a8,&DAT_0040b00e,
         &DAT_0040b4a8);
  fg = fgets_unlocked(*(char **)(buffer + (long)input[0] * 8),128,(FILE *)__stdin_FILE);
  if (fg == (char *)0x0) {
    printf("%s\n[%sSir Alaric%s]: Is this the best you have?!\n\n",&DAT_0040b4e4,&DAT_0040b00e,
           &DAT_0040b4e4);
                    /* WARNING: Subroutine does not return */
    exit(0x45);
  }
  return;
}


```

file: `chal`
```c
┌──(kali㉿kali)-[~/training_PWN/vault_of_lost_memories/challenge]
└─$ checksec --file=chal  
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   No Symbols  No     0               3               chal
```
assembly code tu ghidra: `chal`
```c
undefined4 main(void)
{
  int correct;
  undefined4 val;
  
  banner();
  signal(0xe,FUN_00401230);
  alarm(100);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  correct = game();
  if (correct == 0) {
    val = 0;
    vuln();
  }
  else {
    val = 0xffffffff;
    fwrite("password mismatch!\n",1,23,stderr);
  }
  return val;
}


int game(void)
{
  int true;
  byte *pbVar1;
  size_t len;
  ushort **data_type;
  long in_FS_OFFSET;
  uint i;
  undefined4 j;
  byte buffer [40];
  long canary;
  byte char;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  for (i = 0; i < 32; i = i + 4) {
    pbVar1 = buffer + i;
    pbVar1[0] = 0;
    pbVar1[1] = 0;
    pbVar1[2] = 0;
    pbVar1[3] = 0;
  }
  puts("Welcome to the digital vault of lost memories! ");
  puts("Enter the passcode to enter the lost memory world: ");
  printf(">>> ");
  fflush(stdout);
  fgets((char *)buffer,32,stdin);
  len = strlen((char *)buffer);
  buffer[len - 1] = 0;
  for (j = 0; buffer[j] != 0; j = j + 1) {
    char = buffer[j];
    data_type = __ctype_b_loc();
    if (((*data_type)[(char)char] & 0x100) == 0) {
      data_type = __ctype_b_loc();
      if (((*data_type)[(char)char] & 0x200) != 0) {
        true = DAT_00404094 + (char)char + -0x61;
        buffer[j] = (char)true + (char)(true / 0x1a) * -0x1a + 0x61;
      }
    }
    else {
      true = DAT_00404094 + (char)char + -0x41;
      buffer[j] = (char)true + (char)(true / 0x1a) * -0x1a + 0x41;
    }
    buffer[j] = (byte)DAT_00404090 ^ buffer[j];
  }
  true = memcmp("cLVQjFMjcFDGQ",buffer,0xd);
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return -(uint)(true != 0);
}


void vuln(void)
{
  long in_FS_OFFSET;
  char buffer [136];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  memset(buffer,0,128);
  puts("How should we address you? ");
  printf(">>> ");
  fgets(buffer,128,stdin);
  printf("hello ");
  printf(buffer);
  printf("Here are the lost memories:");
  putc(10,stdout);
  system("ls *.pdf");
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
tu IDA:
````c
__int64 game()
{
  char char_1; // [rsp+7h] [rbp-39h]
  unsigned int i; // [rsp+8h] [rbp-38h]
  int j; // [rsp+Ch] [rbp-34h]
  char buffer[40]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 canary; // [rsp+38h] [rbp-8h]

  canary = __readfsqword(0x28u);

  for ( i = 0; i <= 31; i += 4 )
    *(_DWORD *)&buffer[i] = 0;

  puts("Welcome to the digital vault of lost memories! ");
  puts("Enter the passcode to enter the lost memory world: ");
  printf(">>> ");
  fflush(stdout);
  fgets(buffer, 32, stdin);
  buffer[strlen(buffer) - 1] = 0;
  for ( j = 0; buffer[j]; ++j )
  {
    char_1 = buffer[j];
    if ( ((*__ctype_b_loc())[char_1] & 0x100) != 0 )
    {
      buffer[j] = (char_1 - 65 + dword_404094) % 26 + 65;
    }
    else if ( ((*__ctype_b_loc())[char_1] & 0x200) != 0 )
    {
      buffer[j] = (char_1 - 97 + dword_404094) % 26 + 97;
    }
    buffer[j] ^= dword_404090;
  }
  return (unsigned int)-(memcmp("cLVQjFMjcFDGQ", buffer, 0xDuLL) != 0);
}

with dword_... following from the memory:

.data:0000000000404090 dword_404090    dd 35h                  ; DATA XREF: game+18D↑r

.data:0000000000404094 dword_404094    dd 0Ah 
````
ascii table:

<img width="960" height="639" alt="image" src="https://github.com/user-attachments/assets/e28e305d-900f-49de-9bf2-a4b801ef4d05" />


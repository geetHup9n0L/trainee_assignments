## Task:
```
Task 1: Code asm x64 kết nối đến localhost và gửi nội dung bất kì
Code asm spawn shell
Code asm Open read write file flag.txt
```
___
### Socket kết nối đến localhost
Listen trên 1 terminal:
```c
nc -lvp 4444
```

Socket trong C code: `client.c`  
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

int main(void) {
	int sock;
	struct sockaddr_in server_addr;
	char *txt = "Hello\n";	

	// 1. create a socket (IPv4, TCP)
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock < 0) {
		perror("socket");
		exit(1);
	}

	// 2. describe the server we want to connect to
	server_addr.sin_family = AF_INET;  //IPv4
	server_addr.sin_port = htons(4444); // port 4444
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); //local host


	// 3. connect to the server 
	if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		perror("connect");
		exit(1);
	}

	printf("[+] Connected to localhost:4444\n");

	// 4. send a random message
	send(sock, txt, strlen(txt), 0);

	// 5. close the connection
	close(sock);
	return 0;
}
```
Output:

<img width="802" height="110" alt="image" src="https://github.com/user-attachments/assets/1a0eeb7d-6472-4c06-ae10-d5cdf481a645" />

Trình tự thực thi việc kết nối:
```c
tạo socket() -> tạo địa chỉ server -> kết nối connect() -> send -> đóng connection close()
```

Chuyển sang assembly:
```asm
; write.asm
section .data
	helloTxt db "Hello"
	len equ $-helloTxt

section .text
global _start

_start:
	; create socket
	; // sock = socket(AF_INET, SOCK_STREAM, 0);
	mov rax, 0x29 ; 41 - socket
	mov rdi, 2 
	mov rsi, 1
	mov rdx, 0
	syscall

	mov rbx, rax ; luu lai socket_fd

	; open connection
	; // connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
	mov rdx, 0x0100007F   ; 127.0.01
	push rdx
	mov rdx, 0x5C11 ; 4444
	push dx
	mov rdx, 2
	push dx

	mov rdi, rbx 
	mov rsi, rsp 
	mov rdx, 16
	mov rax, 42
	syscall

	; write random bs
	mov rax, 0x01
	mov rdi, rbx
	mov rsi, helloTxt
	mov rdx, len
	syscall

	; exit
	xor rax, rax
	mov rax, 60
	mov rdi, 0
	syscall
```
Bản cỉa thiện:
```asm
section .data
helloTxt db "Hello", 10
len equ $-helloTxt

section .text
global _start

_start:
    ; taoj socket() và lưu lại fd 
    mov rax, 41          ; sys_socket
    mov rdi, 2           ; AF_INET
    mov rsi, 1           ; SOCK_STREAM
    xor rdx, rdx         ; protocol = 0
    syscall

    mov rbx, rax         ; save sockfd in rbx

    ; xây cấu trúc địa chỉ localhost tren stack
    mov rdx, 0x0100007F  ; 127.0.0.1
    push rdx

    mov rdx, 0x5C11      ; port 4444
    push dx

    mov rdx, 2           ; AF_INET
    push dx

    ; connect() 
    mov rax, 42          ; sys_connect
    mov rdi, rbx         ; sockfd
    mov rsi, rsp         ; pointer to đến cấu trúc trên
    mov rdx, 16          ; size
    syscall

    ; write() viết ra server đang listening
    mov rax, 1           ; sys_write
    mov rdi, rbx         ; sockfd
    mov rsi, helloTxt
    mov rdx, len
    syscall

    ; exit() đóng phiên kết nối
    mov rax, 60
    xor rdi, rdi
    syscall
```

Assemble và link file .asm:
```c
nasm -f elf64 write.asm -o write.o
ld write.o -o write
```
Chạy:
```c
./write 
```
<img width="801" height="97" alt="image" src="https://github.com/user-attachments/assets/a95bf5a3-9dac-41f0-bc0e-293e978375e7" />


### Tạo shell (spawn shell):
* `/bin/sh`: 
```
0x68732f6e69622f
```
<img width="1019" height="632" alt="image" src="https://github.com/user-attachments/assets/03bfa6ab-9cdc-41ca-ac4d-8401f2b04c50" />

* syscall:
<img width="996" height="176" alt="image" src="https://github.com/user-attachments/assets/e7ecbd11-9ace-4de3-950e-d2ab14745b05" />

Assembly code:
```asm
	; spawn shell
	; shel: /bin/sh - 2F 62 69 6E 2F 73 68 - 0x68732f6e69622f
	mov rbx, 0x68732f6e69622f
	push rbx

	; execve("/bin/sh", null, null)
	mov rax, 0x3b ; 59 - execve()
	mov rdi, rsp
	mov rsi, 0	
	mov rdx, 0
	syscall
```
* khi dùng syscall `execve()`, rdi ko được gán trực tiếp hex /bin/sh
* mà rdi phải là con trỏ đến memory
* nên ta đấy giá trị shell lên stack, và cho rdi trỏ đến đấy

Output:

<img width="811" height="137" alt="image" src="https://github.com/user-attachments/assets/4f08419d-a5ec-45e6-bc5a-bb43afc2a151" />

<img width="803" height="105" alt="image" src="https://github.com/user-attachments/assets/bbe1f20e-5148-4de7-8c74-3c99909cef5d" />

### Open, read, write flag.txt từ server:
* tạo flag.txt:

<img width="814" height="118" alt="image" src="https://github.com/user-attachments/assets/67f01240-e0aa-4e34-acf3-53bc7c17569e" />

* `flag.txt`:
```c
0x7478742e67616c66
```
<img width="1036" height="600" alt="image" src="https://github.com/user-attachments/assets/503efe04-fbae-4b0f-aed3-9ce08bdf98fd" />

* các syscall tương ứng cho open, read, write:

<img width="848" height="146" alt="image" src="https://github.com/user-attachments/assets/3ad0c3ab-d00b-4e6a-9bc7-f519fe0e8391" />

Assembly code:
```asm

```

___
Tài liệu:

https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md

https://www.geeksforgeeks.org/c/socket-programming-cc/

https://www.studocu.vn/vn/document/dai-hoc-nguyen-tat-thanh/he-dieu-hanh/2-thao-tac-file-trong-linux/85088160

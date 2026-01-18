Task:
```
Task 1: Code asm x64 kết nối đến localhost và gửi nội dung bất kì
Code asm spawn shell
Code asm Open read write file flag.txt
```
___
### Socket kết nối đến localhost
Listen trên 1 terminal:
```
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
```
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

### Tạo shell (spawn shell):










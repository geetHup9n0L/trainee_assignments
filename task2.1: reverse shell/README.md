## Reverse shell
___
**Shell là gì?**

Shell là một phần mềm cho phép người dùng tương tác với các dịch vụ, tài nguyên của hệ điều hành thông qua giao diện CLI hoặc là terminal. Shell được gọi là vỏ bọc cho hệ điều hành.

**Reverse shell:**

Reverse shell là khi thay vì người dùng chủ động mở phiên kết nối đến một server đang nghe (giống việc sử dụng ssh, telnet,...) thì ở đây quy trình được đảo ngược lại. Vai trò của người dùng bây giờ là lắng nghe các kết nối, còn server sẽ có vai trò là kết nối đến máy chủ của người dùng.

Reverse shell từ server về máy chủ người dùng sẽ cấp shell trên chính terminal của máy chủ người dùng thay vì là sử dụng remote shell trên máy của server. Mọi tương tác trên shell này sẽ thực thi trên shell của server và tác động lên tài nguyên của server y hệt. 

Thông thường, việc users (hoặc là attacker) muốn kết nối đến server để sử dụng remote shell sẽ bị giới hạn và chặn bởi firewall, NAT (Network Address translation). Tuy nhiên, việc kết nối từ server ra bên ngoài, từ mạng nội bộ ra internet lại không bị chọn lọc và chặn bởi firewall hay NAT. Vì thế, attacker thường tận dụng tính năng này để khai thác hoặc kiểm soát server.

Việc khai thác lỗ hổng đó được khai thác trên chính server, khi mà server có những lỗ hổng trong codebase, web,... tạo điều kiện cho attacker đẩy malicious payload lên server, server thực thi nó và kết nối đến máy chủ attacker đang listening, và attacker sẽ thành công giành được shell trên máy mình

Quy trình sẽ là:
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
<img width="438" height="178" alt="image" src="https://github.com/user-attachments/assets/a582c7ab-504a-4e78-8c19-ef2c0a0f2dae" />

___
Tài liệu:

https://www.reddit.com/r/explainlikeimfive/comments/mujbk4/eli5_reverse_shelling_and_shells_in_general/?tl=vi

https://www.imperva.com/learn/application-security/reverse-shell/

https://viblo.asia/p/hieu-ro-ve-reverse-shells-LzD5ddE45jY

https://www.invicti.com/learn/reverse-shell

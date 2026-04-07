### Thông tin file:

```c
└─$ ls
chall  Dockerfile
```
```c
└─$ file chall 
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=df3e70e986fcc294430e2e416a9343018e40b118, for GNU/Linux 4.4.0, not stripped
```
```c
└─$ checksec --file=chall 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   34 Symbols  No     0               3               chall
```
___
Code:

`main()`:
```c
undefined8 main(void)

{
  FILE *fp;
  long in_FS_OFFSET;
  undefined1 flag [32];
  undefined1 buf [264];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  setbuf(stdin,(char *)0x0);
  setbuf(stdout,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  printf("my aura: %p\nur aura? ",&aura);
  fp = fopen("/dev/null","r");
  read(0,fp,256);
  fread(buf,1,8,fp);
  if (aura == 0) {
    puts("u have no aura.");
  }
  else {
    fp = fopen("flag.txt","r");
    fread(flag,1,0x11,fp);
    printf("%s\n ",flag);
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}

```
Bài này là điển hình cho Arbitrary Write 

Lỗ hổng được mô ta trong đoạn code sau:
  ```c
    printf("my aura: %p\nur aura? ",&aura);

    fp = fopen("/dev/null","r");
    read(0,fp,256); 
    fread(buf,1,8,fp);
  ```
* `printf("my aura: %p\nur aura? ",&aura);`: in địa chỉ của biến global `aura` 
* `buffer = fopen("/dev/null","r");`:
  * mở một file dưới chế độ **read**
  * tạo một cấu trúc FILE, được cấp phát trong bộ nhớ và trả lại con trỏ 
* `read(0,fp,256);`:
  * đọc input của ta từ fd 0 (stdin) vào memory của con trỏ
  * phần data đọc vào sẽ overwrite cấu trúc của FILE trong memory
* `fread(buf,1,8,fp);`:
  * hàm read của FILE, đọc 8 bytes từ FILE vào bộ nhớ tạm `buffer` trên memory
  * Rồi từ bộ nhớ tạm `buffer` trên của FILE đưa vào vùng nhớ `buf` trên stack

Tóm lại là ta có khả năng thay đổi FileStructure:
* fopen() cấp phát vùng nhớ cho FILE struct ở đâu đấy trên userland heap memory và trả về con trỏ của địa chỉ đấy
* read() sẽ sử dụng đúng con trỏ đấy là nơi để read data input vào

Có hàm check ngay sau đó:
  ```c
  if (aura == 0) {
    puts("u have no aura.");
  }
  else {
    fp = fopen("flag.txt","r");
    fread(flag,1,0x11,fp);
    printf("%s\n ",flag);
  }
  ```
* nếu giá trị `aura` khác 0 thì đọc flag từ file 
* Đây là `win_variable` mà ta muốn thay đổi

Bên cạnh đấy, khi học đến cấu trúc FILE, giờ ta mới để ý đến:
  ```c
  setbuf(stdin,(char *)0x0);
  setbuf(stdout,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  ```
  `stdin`, `stdout`, `stderr` cũng là các biến global 

  <img width="531" height="570" alt="image" src="https://github.com/user-attachments/assets/0b58c9ac-3e44-441d-aa26-594ec60c565c" />


___
### Exploit:
Vậy mục tiêu là lấy địa chỉ leak của `aura` rồi tiêm vào vùng nhớ cấu trúc File qua read()

Sau đấy khi `fread` được gọi, read sẽ dựa vào các trường của `buffer` trong cấu trúc File, để đưa data bất kỳ từ file vào vùng memory đấy. Trng trường hợp này, địa chỉ `buffer` sẽ trở thành địa chỉ của `aura`. Và nếu giá trị `aura` thay đổi (khác 0) thì ta sẽ có flag.

Để dễ dàng thực hiện khai thác trên, pwntools có một hàm vô cùng tiện lợi:
```python
fp = FileStructure()
```
Nó sẽ trả về một python object tượng trưng cho `FILE struct`, có các trường giống như trong C

<img width="807" height="586" alt="image" src="https://github.com/user-attachments/assets/1d5e1399-adfc-4252-859f-736808424e73" />

Và có thể thay đổi được giá trị của các trường trong object này

<img width="810" height="494" alt="image" src="https://github.com/user-attachments/assets/bc525e0c-345c-4ca3-b438-a97ea1aab6e3" />

Vậy nên ta có thể tận dụng hàm này để chỉnh sửa File struct tùy theo hướng khai thác

Hai fields duy nhất cần chỉnh để có Arbitrary Write, là: `_IO_buf_base` và `_IO_buf_end` - hai trường này sẽ xác định vùng nhớ của buffer. 

Ta đổi giá trị của: buf_base = `aura`, buf_end = `aura + len`. 

Trong pwntools cũng có hàm để thay đổi 2 trường trên cho ta:
```python
payload = fp.read(aura_addr, 10)
```
Ta sẽ set size = 10, lớn hơn size trong `fread(buf,1,8,fp)` là 8 để có thể refill hợp lệ sang địa chỉ mới này

Các fields còn lại sẽ bị set về NULL

<img width="807" height="594" alt="image" src="https://github.com/user-attachments/assets/57af73bb-70c0-4be2-8dec-953045a1758c" />

Theo nguyên lý ban đầu, thì bây giờ `fread()` sẽ đọc data từ FILE vào vùng nhớ `aura`

Nhưng lúc này, chương trình không kết thúc mà lại yêu cầu input trên terminal:

<img width="803" height="600" alt="image" src="https://github.com/user-attachments/assets/0aa08e50-6f7a-4147-9244-f49549678564" />

Và khi ta điền input thì ra được flag

Đó là bởi vì một trường trong cấu trúc FILE:

<img width="805" height="610" alt="image" src="https://github.com/user-attachments/assets/7771804e-27af-496e-ba5e-55158d92a390" />

`fileno: 0x0` đồng nghĩa với luồng stdin (bằng 0x0 vì ở trên)

Vậy nên mặc dù gọi đến `fread(buf,1,8,fp)`, đáng lẽ lấy luồng data từ `fp`, nhưng vì `fileno` đã chuyển luồng thành luồng stdin - lấy data input từ ta. Và bên cạnh đó, thay vì read data vào bộ nhớ tạm `buffer` của FILE, thì giờ nó overwrite data vào vùng `aura` (bởi vì ta đã thay đổi con trỏ `buf_base`) làm thay đổi gái trị NULL bên trong. Từ đấy lấy được flag 

`script.py`:
```python
```
___
reference:

https://www.youtube.com/watch?v=Tv1Rss5Vqpk&t=490s

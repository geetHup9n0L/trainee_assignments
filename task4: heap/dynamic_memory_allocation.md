Task:
```
Tìm hiểu về cấp phát động (malloc, alloc, ...), hàm free, cách các loại bin (tcache, fastbin, unsorted bin, ...) hoạt động
Với mấy cái cấu trúc của chunk, bin
```
___

## Ly thuyet 
### Cấp phát động và Heap (Dynamic memory allocation)
Là một quá trình cấp phát bộ nhớ từ heap tại thời gian thực thi của chương trình (at runtime), thay vì là tại thời gian biên dịch chương trình (at compile time). Điều này cho phép chương trình đang chạy có thể linh hoạt trong việc quản lý bộ nhớ dựa trên kích thước đầu vào (input) khác nhau, mà không bị cố định độ lớn của bộ nhớ ngày từ đầu chương trình. Thường được sử dụng trong C/C++ để tương tác với bộ nhớ heap.

So với Stack, mỗi vùng nhớ được thể hiện = stack frame, thì trên heap mỗi vùng nhớ gọi là heap chunk

**Có các functions sau để cấp phát bộ nhớ trên heap:**

* `malloc(size)`: cấp phát một khối bộ nhớ với kích thước của bytes
* `calloc(n, size)`: cấp phát nhiều khối bộ nhớ (n khối) với kích thước của bytes, đồng thời khởi tạo tròng vùng nhớ với giá trị 0. (với malloc() thì chứa giá trị rác bên trong vùng nhớ được cấp)
* `realloc(ptr, new_size)`: cho phép thay đổi kích thước của khối bộ nhớ được cấp phát trước đó. Bên cạnh đấy, realloc() cũng có thể đóng vai trò của malloc() và free(). 

Các functions trả về con trỏ `void *` chứa địa chỉ byte đầu tiên của vùng nhớ được cấp phát 

Khác với stack (khi return thì bỏ qua phần memory trong stack frame, có thể overwrite phần memory đấy khi một function khác được gọi), bất kỳ bộ nhớ nào trên heap được cấp phát động vẫn sẽ trong trạng thái cấp phát xuyên suốt chương trình. Vì vậy, yêu cầu phải thủ công giải phóng phần bộ nhớ đấy với:
* `free(ptr)`: Giải phóng vùng bộ nhớ được cấp phát trước đó, tránh bị rò rỉ thông tin từ bộ nhớ. 

Khi được cấp phát động, mỗi heap chunk không chỉ bao gồm mỗi bộ nhớ yêu cầu được cấp phát (giả sử 0x10 bytes - malloc(0x10)) trên heap mà còn bào gồm cả heap metadata. Phần metadata/header nằm trước phần chunk và chiếm 0x10 bytes theo cấu trúc x64:
```c
ptr = malloc(0x10)
```
```c
0x0:    0x00     - Previous Chunk Size
0x8:    0x21     - Chunk Size
0x10:   "long"     - Content of chunk
```
* `prev_size`: thông tin về kích thước chunk trước đã được giải phóng (free())
* `chunk_size`: kích thương của heap chunk, to hơn so với kích thước cấp phát mong muốn với malloc() (+ 0x10 bytes phần metadata). Đồng thời chứa flag ở 3 bit cuối:
  * `PREV_INUSE (0x1)`	chunk trước đang được dùng (chưa được free() nên prev_size = 0 - chưa giải phóng byte nào)
  * `IS_MMAPPED (0x2)`	dùng mmap
  * `NON_MAIN_ARENA (0x4)`	thuộc arena khác 
* `chunk`: ptr trỏ đến vị trí này, và đây là nơi chứa data từ chương trình, có kích thước đúng = kích thước yêu cầu cấp phát ban đầu của malloc() 

Code trong c:
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
	char *ptr;
	ptr = malloc(0x10);

	strcpy(ptr, "Long");

	return 0;
}
```
Chạy trong gdb-pwndbg và tìm phần heap chunk tương ứng:
```asm
pwndbg> search Long
Searching for byte: b'Long'
heap            0x555555555155 outsd dx, dword ptr [rsi]
[heap]          0x5555555592a0 0x676e6f4c /* 'Long' */
```
```asm
pwndbg> x/4xg 0x555555559290
0x555555559290: 0x0000000000000000      0x0000000000000021  // prev_size = 0 | chunk_size = 0x20 ; flag = 0x01
0x5555555592a0: 0x00000000676e6f4c      0x0000000000000000  // chunk_data = "Long" <== địa chỉ malloc() trả về cho ptr
```
hoặc với lệnh `heap` cho ra thông tin cụ thể hơn:
```asm
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
Size: 0x290 (with flag bits: 0x291)

Allocated chunk | PREV_INUSE
Addr: 0x555555559290
Size: 0x20 (with flag bits: 0x21)

Top chunk | PREV_INUSE
Addr: 0x5555555592b0
Size: 0x20d50 (with flag bits: 0x20d51)
```
```asm
pwndbg> heap -v
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
prev_size: 0x00
size: 0x290 (with flag bits: 0x291)
fd: 0x00
bk: 0x00
fd_nextsize: 0x00
bk_nextsize: 0x00

Allocated chunk | PREV_INUSE
Addr: 0x555555559290
prev_size: 0x00
size: 0x20 (with flag bits: 0x21)
fd: 0x676e6f4c
bk: 0x00
fd_nextsize: 0x00
bk_nextsize: 0x20d51

Top chunk | PREV_INUSE
Addr: 0x5555555592b0
prev_size: 0x00
size: 0x20d50 (with flag bits: 0x20d51)
fd: 0x00
bk: 0x00
fd_nextsize: 0x00
bk_nextsize: 0x00
```
* Chunk đầu tiền với size 0x290 là heap chunk được glibc cấp phát cho internal structures (glibc gọi malloc() lúc đầu chương trình)
* Chunk với size 0x20 là mình cấp phát động
* `Top chunk`: phần memory heap còn lại chưa dùng. Khi dùng malloc() sẽ lấy memory từ đây, top chunk khi đấy cũng giảm tương ứng
  ```
  [ new chunk ] + [ smaller top chunk ]
  ```
  (hình dung: heap - top chunk, stack - rsp)

<img width="805" height="818" alt="image" src="https://github.com/user-attachments/assets/e253b6c7-0af1-45e1-81d7-7b271f867802" />

<img width="814" height="683" alt="image" src="https://github.com/user-attachments/assets/c68ba6d3-736a-4d2a-a493-bdae4b5be7dc" />


### Bins (Ngăn xếp)
Khi không dùng đến phần bộ nhớ được cấp phát động nữa, ta giải phỏng với hàm `free()`. Hàm `free()` không làm chunk biến mất, mà đưa nó vào các **danh sách bins** Với mục đích là có thể tái sử dụng các khối bộ nhớ này cho những lần cấp phát động bằng malloc() tiếp theo. Gọi là freed chunks. Khi mà chương trình yêu cầu cấp phát bộ nhớ, phần heap sẽ kiểm tra các bin có chưa chunk nào đủ lớn để đáp ứng yêu cầu cấp phát trên, nếu tìm thấy sẽ loại bỏ chunk khỏi bin và trả về địa chỉ của vùng nhớ về như malloc().

free flow:
````c
if (tcache chưa đầy)
    push vào tcache

else if (fastbin size)
    push fastbin

else
    đưa vào unsorted bin
    có thể coalesce
````
malloc flow:
````c
if (tcache có)
    return tcache chunk

if (fastbin có)
    return fastbin chunk

if (smallbin có)
    return smallbin chunk

if (unsorted bin có)
    xử lý

if (largebin có)
    best-fit

else
    dùng top chunk
````

Có các loại chunks thứ tự tương ứng với hiệu năng và chức năng sau:

1. `tcache`
	* Nó là cache riêng của thread hoặc là mỗi thread có một tcache riêng, còn với fastbin thì bao nhiêu thread cũng chỉ dùng 1 fastbin. Xuất hiện ở bản libc 2.26 trở đi. Giống fastbin, là theo phương pháp LIFO. Một list tcache chỉ giữ được 7 chunk cùng một lúc cho một size và có tổng cộng 64 tcache lists với `idx = 0 -> 63` tương ứng với các kích thước trong dải `0x20 - 0x410`. Nếu ngăn xếp bị đầy (full 7 chunk của một size), thì chunk thứ 8 sẽ được đẩy xuống ngăn xếp của fastbin.

	* Mô phỏng:
	```c
	int main() {
		char* p1 = malloc(0x20);
		char* p2 = malloc(0x20);
		char* p3 = malloc(0x20);
		char* p4 = malloc(0x20);
		char* p5 = malloc(0x20);
		char* p6 = malloc(0x20);
		char* p7 = malloc(0x20);
		char* p8 = malloc(0x20);
	
		free(p1);
		free(p2);
		free(p3);
		free(p4);
		free(p5);
		free(p6);
		free(p7);
		free(p8);
	
		return 0;
	}
 	```
	```asm
 	pwndbg> heap -v
	Allocated chunk | PREV_INUSE
	Addr: 0x555555559000
	prev_size: 0x00
	size: 0x290 (with flag bits: 0x291)
	fd: 0x10000
	bk: 0x00
	fd_nextsize: 0x00
	bk_nextsize: 0x00
	
	Free chunk (tcachebins) | PREV_INUSE
	Addr: 0x555555559290
	prev_size: 0x00
	size: 0x30 (with flag bits: 0x31)
	fd: 0x555555559
	bk: 0x230686f4a65f4952
	fd_nextsize: 0x00
	bk_nextsize: 0x00
	
	Allocated chunk | PREV_INUSE
	Addr: 0x5555555592c0
	prev_size: 0x00
	size: 0x30 (with flag bits: 0x31)
	fd: 0x00
	bk: 0x00
	fd_nextsize: 0x00
	bk_nextsize: 0x00
 	...
 	```
 	
 	```asm
  	# Free 1 lần
	pwndbg> bins
	tcachebins
	0x30 [  1]: 0x5555555592a0 ◂— 0
	fastbins
	empty
	unsortedbin
	empty
	smallbins
	empty
	largebins
	empty
  	```
  	```asm
   	# Free 8 lần
	pwndbg> bins
	tcachebins
	0x30 [  7]: 0x5555555593c0 —▸ 0x555555559390 —▸ 0x555555559360 —▸ 0x555555559330 —▸ 0x555555559300 —▸ 0x5555555592d0 —▸ 0x5555555592a0 ◂— 0
	fastbins
	0x30: 0x5555555593e0 ◂— 0
	unsortedbin
	empty
	smallbins
	empty
	largebins
	empty
   	```
2. `fastbin`
	* Nếu free một chunk có kích thước từ `0x20 -> 0x80`, thì cái chunk sẽ được đưa vào ngăn xếp fastbin. Fastbin có tổng 7 linked lists từ `idx = 0 -> 6`  tương ứng với size của freed chunk. Để khi lần malloc() tới với kích thước trong khoảng 0x20 -> 0x80 sẽ kiểm tra chunk thỏa mãn trong fastbin và lấy nó. Chú ý là lúc free chunk là bao gồm cả metadata + userdata, nên phần chunk được free không phải là kích thước ban đầu lúc malloc() (Ví dụ: malloc(0x20) -> chunk = 0x30 -> freed chunk vào bins = 0x30).
	```c
	int main() {
		char* p1 = malloc(0x10);
		free(p1);
	
		return 0;
	}
	```
	```asm
	────────────────────── Fastbins for arena 0x7ffff7dd1b20 ──────────────────────
	Fastbins[idx=0, size=0x10]  ←  Chunk(addr=0x602010, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x602030, size=0x20, flags=PREV_INUSE)
	Fastbins[idx=1, size=0x20]  ←  Chunk(addr=0x602050, size=0x30, flags=PREV_INUSE)
	Fastbins[idx=2, size=0x30]  ←  Chunk(addr=0x602080, size=0x40, flags=PREV_INUSE)
	Fastbins[idx=3, size=0x40]  ←  Chunk(addr=0x6020c0, size=0x50, flags=PREV_INUSE)
	Fastbins[idx=4, size=0x50]  ←  Chunk(addr=0x602110, size=0x60, flags=PREV_INUSE)
	Fastbins[idx=5, size=0x60]  ←  Chunk(addr=0x602170, size=0x70, flags=PREV_INUSE)
	Fastbins[idx=6, size=0x70]  ←  Chunk(addr=0x6021e0, size=0x80, flags=PREV_INUSE)
 	```
 	* Fastbin theo phương thức LIFO, chunk cuối được đẩy vào fastbin thì cũng là chunk đầu tiên được lấy ra nếu malloc() yêu cầu
3. `unsorted bin`, `smallbin`, `largebin`
* Khác với dạng danh sách liên kêt đơn của fastbin/tcache, ba loại bin này theo danh sách liên kết đôi. Nghĩa là các chunk sẽ trỏ đến chunk trước và ngược lại.
* Khi mà các freed chunks quá lớn so với kích thước cho phép của tcache (> 0x410) và fastbin (> 0x80), hoặc khi mà ngăn xếp tcache và fastbin bị đầy, các chunk này sẽ được đẩy đến `unsortedbin`. Và các chunk ở trong `unsortedbin` có khả năng gộp vào nhau thành một chunk lớn hơn.
```c
int main() {

	char* p1 = malloc(0x410);
	char* p2 = malloc(0x410);

	free(p1);
	free(p2);

	return 0;
}
```
```asm
pwndbg> bins
tcachebins
empty
fastbins
empty
unsortedbin
all: 0x555555559290 —▸ 0x7ffff7f8fb20 (main_arena+96) ◂— 0x555555559290
smallbins
empty
largebins
empty

pwndbg> heap -v
Allocated chunk | PREV_INUSE
Addr: 0x555555559000
prev_size: 0x00
size: 0x290 (with flag bits: 0x291)
fd: 0x00
bk: 0x00
fd_nextsize: 0x00
bk_nextsize: 0x00

Free chunk (unsortedbin) | PREV_INUSE
Addr: 0x555555559290
prev_size: 0x00
size: 0x420 (with flag bits: 0x421)
fd: 0x7ffff7f8fb20
bk: 0x7ffff7f8fb20
fd_nextsize: 0x00
bk_nextsize: 0x00

Allocated chunk
Addr: 0x5555555596b0
prev_size: 0x420
size: 0x420 (with flag bits: 0x420)
fd: 0x00
bk: 0x00
fd_nextsize: 0x00
bk_nextsize: 0x00

Top chunk | PREV_INUSE
Addr: 0x555555559ad0
prev_size: 0x00
size: 0x20530 (with flag bits: 0x20531)
fd: 0x00
bk: 0x00
fd_nextsize: 0x00
bk_nextsize: 0x00
```

### Những lỗ hổng liên quan đến heap:
* use-after-frees
* double-frees
* heap-overflows




____
docs:

https://azeria-labs.com/heap-exploitation-part-1-understanding-the-glibc-heap-implementation/

https://guyinatuxedo.github.io/25-heap/index.html

https://www.youtube.com/watch?v=xDVC3wKjS64&t=702s











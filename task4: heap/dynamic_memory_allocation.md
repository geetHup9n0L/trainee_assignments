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
```
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
```
pwndbg> x/4xg 0x555555559290
0x555555559290: 0x0000000000000000      0x0000000000000021  // prev_size = 0 | chunk_size = 0x20 ; flag = 0x01
0x5555555592a0: 0x00000000676e6f4c      0x0000000000000000  // chunk_data = "Long"
```
<img width="805" height="818" alt="image" src="https://github.com/user-attachments/assets/e253b6c7-0af1-45e1-81d7-7b271f867802" />


### Bins


### Những lỗ hổng liên quan đến heap:
* use-after-frees
* double-frees
* heap-overflows




____
docs:

https://azeria-labs.com/heap-exploitation-part-1-understanding-the-glibc-heap-implementation/

https://guyinatuxedo.github.io/25-heap/index.html











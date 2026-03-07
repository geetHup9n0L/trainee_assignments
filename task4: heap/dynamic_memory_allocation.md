Task:
```
Tìm hiểu về cấp phát động (malloc, alloc, ...), hàm free, cách các loại bin (tcache, fastbin, unsorted bin, ...) hoạt động
Với mấy cái cấu trúc của chunk, bin
```
___

## Ly thuyet 
### Cấp phát động (Dynamic memory allocation)
Là một quá trình cấp phát bộ nhớ từ heap tại thời gian thực thi của chương trình (at runtime), thay vì là tại thời gian biên dịch chương trình (at compile time). Điều này cho phép chương trình đang chạy có thể linh hoạt trong việc quản lý bộ nhớ dựa trên kích thước đầu vào (input) khác nhau, mà không bị cố định độ lớn của bộ nhớ ngày từ đầu chương trình.

So với Stack, ...

Có các functions sau để cấp phát bộ nhớ trên heap:

* `malloc(size)`: cấp phát một khối bộ nhớ với kích thước của bytes
* `calloc(n, size)`: cấp phát nhiều khối bộ nhớ (n khối) với kích thước của bytes, đồng thời khởi tạo tròng vùng nhớ với giá trị 0. (với malloc() thì chứa giá trị rác bên trong vùng nhớ được cấp)
* `realloc(ptr, new_size)`: cho phép thay đổi kích thước của khối bộ nhớ được cấp phát trước đó. Bên cạnh đấy, realloc() cũng có thể đóng vai trò của malloc() và free(). 

Khác với stack, ...
* `free(ptr)`: Giải phóng vùng bộ nhớ được cấp phát trước đó, tránh bị rò rỉ thông tin từ bộ nhớ. 

### Potential vuln

### Bieu dien tren memory + gdbpwndbg







docs:

https://www.youtube.com/watch?v=S7TPgGCZdeU&t=26s

https://guyinatuxedo.github.io/25-heap/index.html











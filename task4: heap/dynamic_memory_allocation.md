Nói đơn giản thì malloc là hàm yêu cầu kernel cấp phát một ít bộ nhớ. Bạn chỉ định muốn bao nhiêu bộ nhớ tính bằng byte và nhận lại một con trỏ trỏ đến bộ nhớ đó. Bộ nhớ được lưu trữ trên heap. Không giống như stack, các biến trên heap không bị out of scope nên bạn cần giải phóng chúng thủ công bằng cách gọi free(con trỏ đến bộ nhớ được cấp phát bằng malloc). Dùng malloc tốt nếu bạn muốn một ít bộ nhớ mà nhiều phần trong chương trình của bạn sẽ dùng, bạn chỉ cần trỏ đến. Ngoài ra, nếu bạn muốn lưu trữ một lượng lớn dữ liệu (như game textures) bạn nên lưu trữ nó trên heap vì stack có giới hạn kích thước rất nhỏ ~khoảng 1MB. Cũng không nên dùng malloc thường xuyên vì nó chậm.

Dynamic memory allocation is the process of allocating memory on the heap during program runtime, rather than at compile time, allowing for flexible memory management based on input size. Managed via pointers, it enables creating structures whose size is determined at runtime, requiring manual freeing to prevent memory leaks.

Heap Memory: Unlike the stack, the heap provides a large pool of memory for dynamic allocation.
malloc(size): Allocates a contiguous block of memory of size bytes, initialized with garbage values.
calloc(n, size): Allocates multiple blocks of memory, initializing all bytes to zero.
realloc(ptr, new_size): Resizes previously allocated memory blocks.
free(ptr): Releases allocated memory back to the system to prevent memory leaks.








docs:

https://www.youtube.com/watch?v=S7TPgGCZdeU&t=26s











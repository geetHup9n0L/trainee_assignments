## File Stream Oriented Programming (FSOP)

FSOP là một kỹ thuật khai thác lỗ hổng nâng cao, tận dụng cấu trúc `FILE` (hay còn gọi là `_IO_FILE`) có sẵn trong thư viện của C chuẩn - dùng để quản lý các luồng nhập/xuất (I/O) tệp tin. 

___
### Cấu trúc của `_IO_FILE`:

Trong thư viện C tiêu chuẩn (glibc), với mỗi kiểu file I/O (như `stdin`, `stdout`, `stderr`) được cấu thành và quản lý bởi cấu trúc `struct _IO_FILE`.

Và cấu trúc trên sử dụng kỹ thuật **Buffered I/O system** - kỹ thuật sử dụng một vùng nhớ tạm thời (bộ đệm - buffer) để làm trung gian lưu trữ dữ liệu giữa ứng dụng và và file. Phương pháp này nhằm tối ưu hóa hiệu năng thông qua việc gom nhiều thao tác I/O nhỏ thành một lần truyền dữ liệu lớn, giảm số lần gọi hệ thống (system calls).

Các trường trong cấu trúc bao gồm:

```c
struct _IO_FILE {
    int       _flags;           // Magic number + status flags
    char     *_IO_read_ptr;     // Current read position
    char     *_IO_read_end;     // End of read buffer
    char     *_IO_read_base;    // Start of read buffer
    char     *_IO_write_base;   // Start of write buffer
    char     *_IO_write_ptr;    // Current write position
    char     *_IO_write_end;    // End of write buffer
    char     *_IO_buf_base;     // Start of reserve area
    char     *_IO_buf_end;      // End of reserve area
    // ...various fields...
    struct _IO_FILE  *_chain;   // Linked list of all open FILE objects
    int               _fileno;  // File descriptor
    // ...
};
```

Có trường `_flags` điều khiển cách luồng hoạt động, với các giá trị:

| Flag | Value | Meaning |
| :--- | :--- | :--- |
| `_IO_MAGIC` | `0xFBAD0000` | Required magic number in high bits |
| `_IO_UNBUFFERED` | `0x0002` | No buffering |
| `_IO_NO_READS` | `0x0004` | Reading not allowed |
| `_IO_NO_WRITES` | `0x0008` | Writing not allowed |
| `_IO_CURRENTLY_PUTTING` | `0x0800` | Currently in write mode |
| `_IO_IS_APPENDING` | `0x1000` | Append mode |

Bởi vì vùng nhớ buffer của `FILE` nằm trong vùng nhớ, ta có thể overwrite vào các trường và điều khiển nơi glibc có thể đọc data vào hoặc viết data từ đó ra. Khi đó, ta khả năng có:

* Arbitrary Write: sử dụng `fread()` overwrite vào địa chỉ vùng nhớ ta chọn
* Arbitrary Read: sử dụng `fwrite()` leak data từ vùng nhớ bất kỳ ra file/stdout

Trong bản mới hơn `_IO_FILE_plus`, giới thiệu đến trường `vtable` - được bổ sung vào cấu trúc `_IO_FILE` trước đó:
```c
struct _IO_FILE_plus
{
  FILE file;            /* The struct described in the table above */
  const struct _IO_jump_t *vtable; /* The jump table pointer at offset 0xd8 */
};
```

Đặc biệt có trường `_chain`: là một chuỗi danh sách liên kết đơn nối các đối tượng kiểu `FILE` với nhau, xuất phát từ con trỏ `_IO_list_all`. Khi chương trình gọi đến `exit()`, chương trình glibc sẽ gọi đến `_IO_flush_all_lockp`, thực hiện các phương thức `vtable` của mỗi đối tượng trong danh sách

### Cấu trúc của `_IO_jump_t` Vtable:
Cấu trúc của `vtable` là cấu trúc bao gồm các **con trỏ hàm**, được sử dụng trong các quá trình thao tác file: 

```c
struct _IO_jump_t {
    size_t __dummy;
    size_t __dummy2;
    _IO_finish_t    __finish;        // [2]  called by fclose
    _IO_overflow_t  __overflow;      // [3]  called when write buffer is full
    _IO_underflow_t __underflow;     // [4]  called when read buffer is empty
    _IO_uflow_t     __uflow;         // [5]
    _IO_pbackfail_t __pbackfail;     // [6]
    _IO_xsputn_t    __xsputn;        // [7]  fwrite/fputs dispatcher
    _IO_xsgetn_t    __xsgetn;        // [8]
    _IO_seekoff_t   __seekoff;       // [9]
    _IO_seekpos_t   __seekpos;       // [10]
    _IO_setbuf_t    __setbuf;        // [11]
    _IO_sync_t      __sync;          // [12] called by fflush
    // ...
};
```
Bởi vì trong các cấu trúc `FILE` tồn tại một **vtable pointer** (`_IO_jump_t *vtable`) và các `fields`, đều nằm trong vùng nhớ **writable** và được sử dụng trong quá trình nhập/xuất (I/O) qua các hàm như: `fopen`, `fclose`, `fflush`, `exit`,...

Nên cái cốt lõi của FSOP nằm ở việc: nếu ta có thể overwrite giá trị con trỏ `vtable` trong cấu trúc `FILE` (hoặc các con trỏ hàm nằm trong cấu trúc `vtable`), thì trong các đợt nhập/xuất I/O tới sẽ kích hoạt các hàm này

___
### Các phương thức khai thác `FILE` qua các phiên bản libc: 




### Các kỹ thuật phổ biến:

1. Classic FSOP — Vtable Hijacking (pre-glibc 2.24)

Các bản glibc trước 2.24, không có sự kiểm tra hay xác thực trên con trỏ `vtable`. Nên ta có thể thực hiện khai thác như ý tưởng trên:
* Tạo một cấu trúc `_IO_FILE` giả trên vùng nhớ writable bất kỳ (có thể là heap, BSS)
* Overwrite giá trị con trỏ của `vtable` đến một cấu trúc `_IO_jump_t` giả, thực chất là địa chỉ shellcode hoặc `one_gadget`
* Ta nhét cái khối `FILE` giả này vào danh sách `_IO_list_all` (thông qua việc heap exploit)
* Cuối cùng, gọi `exit()` hoặc `fflush()`, glibc sẽ chạy qua danh sách, gọi đến một con trỏ hàm trong `vtables` (như `__overflow` hoặc `__finish`) giả của mình --> thực thi code

2. House of Orange - `_IO_str_overflow` (glibc 2.23 - 2.24)

















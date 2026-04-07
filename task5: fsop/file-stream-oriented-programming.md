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

Các trường trên giúp các hàm có thể tương tác giữa file và buffer. Ta lấy ví dụ 2 hàm là `fread()` và `fwrite()` của file
* Cách `fread()` hoạt động: Đọc từ File -> Memory
  Khi gọi đến `fread()`, nó không gọi đến kernel ngay. Mà kiểm tra buffer trước:
  ```c
    Full buffer layout in memory:
    ┌────────────────────────────────────────────────────┐
    │  _IO_buf_base                          _IO_buf_end │
    │  ┌──────────┬──────────────────┬───────────────┐   │
    │  │ Already  │   Unread bytes   │  Unused space │   │
    │  │  read    │  (valid data)    │  (if small    │   │
    │  └──────────┴──────────────────┴───────────────┘   │
    │  ^          ^                  ^                   │
    │ read_base  read_ptr          read_end              │
    └────────────────────────────────────────────────────┘
  ```
  * `fread()` kiểm tra `read_ptr < read_end` - nếu đúng, data đã có trong buffer, chuyển data vào biến `buf`
  * con trỏ `read_ptr` di chuyển tiếp
  * khi mà `read_ptr == read_end` (buffer đã cạn kiệt/đã đọc xong), glibc gọi đến `read()` syscall để refill cái buffer từ `buf_base` đến `buf_end`, tái sử dụng lại buffer từ đầu
  * nếu dữ liệu trong file bé hơn buffer, thì phần thừa ra để nguyên
 
* Cách `fwrite()` hoạt động: Viết từ Memory -> Fil
  Tương tự, `fwritw()` không trực tiếp viết ra ổ đĩa. Mà thông qua buffer:
  ```c
    Write buffer layout in memory:
    ┌──────────────────────────────────────────────────┐
    │  _IO_buf_base                        _IO_buf_end │
    │  ┌──────────────────┬────────────────────────┐   │
    │  │  Bytes to write  │  Next writes go here   │   │
    │  │  (pending flush) │                        │   │
    │  └──────────────────┴────────────────────────┘   │
    │  ^                  ^                ^           │
    │ write_base       write_ptr        write_end      │
    └──────────────────────────────────────────────────┘
  ```
  * `fwrite()` copy data vòa buffer tại `write_base`, rồi tịnh tiến theo con trỏ `write_ptr` trong buffer
  * data giữ nguyên trong buffer, chưa tương tác gì với ổ đĩa
  * khi buffer đầy rồi, `fflush()`/`fclose()` được gọi, glibc sẽ flush đống data trong buffer, viết từ `write_base` đến `write_ptr` ra file
  * sau khi flush, con trỏ `write_ptr` sẽ reset về `write_base`

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

___
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
Các phương pháp FSOP sẽ khác nhau phụ thuộc vào các bản libc của chương trình:

* `libc <= 2.23`:
  - Không có sự kiểm tra trên con trỏ vtable
  - Có thể khai thác thông qua việc overwrite giá trị con trỏ của trường vtable với địa chỉ bất kỳ trong vùng nhớ (stack, heap, bss), nơi mà có chứa cấu trúc vtable giả tạo. Có các kỹ thuật như là: House of Orange hoặc chiếm đoạt vtable thông thường

 * `libc 2.24 - 2.27` (có `_IO_vtable_check`)
   - Glibc phiên bản này giới thiệu đến hàm `IO_validate_vtable()`. Trước khi bất kỳ hàm vtable nào được gọi đến, glibc sẽ kiểm tra xem địa chỉ con trỏ của trường vtable có nằm trong vùng nhớ read-only `__libc_IO_vtables` không. Nếu nó trỏ đến vùng nhớ heap hoặc stack, thì chương trình abort
   - Bây giờ không thể trỏ vtable đến vùng nhớ theo ý chọn. Thay vào đó, ta phải trỏ vtable đến các khối vtables hợp lệ. Một cách bypass phổ biến là `_IO_str_jumps` bypass. Bằng cách trỏ vtable đến `_IO_str_jumps` (dùng cho `printf`), ta có thể khai thác các hàm `_IO_str_overflow` hoặc `_IO_str_finish`, hàm có chứa lời gọi đến địa chỉ bên trong cấu trúc `FILE` (`_s._allocate_buffer`), cho phép thực thi code. Chỉ cần chỉnh các trường trong cấu trúc một cách hợp lý thì có thể gọi đến system("bin/sh")
  
* `libc >= 2.28`
  - Bên glibc đã vá lại cái `_IO_str_jumps` bypass, loại bỏ lỗ hổng thông qua việc không cho các luồng string gọi đến các con trỏ hàm trong cấu trúc `FILE` để được cấp phát. Trong các bản mới hơn (2.32+) giới thiệu đến mangling (safe-linking) cho tcache/fastbins, và bản 2.34 xóa bỏ `__malloc_hook` và `__free_hook` hoàn toàn.
  - Hướng tới các kỹ thuật mới hơn (House of Apple, House of Kiwi, House of Emma). Những kỹ thuật vấn tuân theo cái check của vtable, nhưng giờ sẽ khai thác con trỏ `_wide_data` hoặc các hàm nằm sâu bên trong vtables như `_IO_wfile_jumps`. Thường phải dựa vào một số flags cụ thể để đưa glibc về kiểu ký tự rộng để rồi cho phép điều khiển thanh ghi hoặc thực thi code. 

___
### Các kỹ thuật phổ biến:

Để có thể khai thác các cấu trúc `FILE` thường phải tồn tại trước các lỗ hổng bộ nhớ. Nổi bật là các lỗ hổng liên quan đến heap như là Use-After-Free (UAF) hoặc Double Free được sử dụng để tạo một cấu trúc `_IO_FILE` trên heap hoặc overwrite cái có sẵn (như stdin, stdout, or stderr). Tool như `pwntool` hỗ trợ tạo các đối tượng `FileStructure` này.

1 - Arbitrary Read / Arbitrary Write:

Bằng cách khai thác các con trỏ buffer bên trong cấu trúc `FILE` (như là _IO_write_base, _IO_write_ptr, _IO_read_base, and _IO_buf_end), ta bắt chương trình phải đọc hoặc viết vào vùng nhớ bất kỳ

* **Arbitrary Read**: qua `fread()` viết vào memory
  * File được mở ở chế độ **read**
  * set `_flag`: cho `_IO_NO_READS` = 0
  * set `_IO_read_ptr == _IO_read_end` (để bắt chương trình refill lại bộ nhớ)
  * set `_IO_buf_base` = target address để viết vào
  * set `_IO_buf_end` = target address + length (độ dài của vùng nhớ)
  * set các con trỏ khác = NULL
 
  Khi `read_ptr` == `read_end`, glibc thấy buffer đã cạn kiệt, lúc này gọi tới `read()` syscall để refill bộ nhớ đấy bằng cách cho `read_ptr` quay về `buf_base`, nhưng giờ địa chỉ vùng nhớ `_IO_buf_base` bị thay đổi thành target của ta (`win_variable`). Khi đấy, syscall viết input của ta trực tiếp vào `win_variable`
  ```c
    [ _IO_buf_base ]————————————[ _IO_buf_end ]
          ↑                             ↑
      target addr              target addr + N
           ← data from file gets written here →
  ```

* **Arbitrary Write**: qua `fwrite()` leak từ memory
  * File được mở ở chế độ **write**
  * set `_flag`: cho `_IO_NO_WRITES` = 0
  * set `_IO_write_base` = địa chỉ vùng nhớ muốn leak
  * set `_IO_write_ptr` = target address + length (kích thước vùng nhớ)
  * set `_IO_read_end == _IO_write_base`
  * set các con trỏ khác = NULL
 
  Khi mà glibc flush đống data trong buffer, sẽ leak các data trong vùng `write_base` và `write_ptr` ra file
  ```c
    [ _IO_write_base ]————————[ _IO_write_ptr ]
            ↑                          ↑
       secret_value            secret + N bytes
          ← these bytes get flushed to the file →
  ```
Vì glibc không kiểm tra các con trỏ buffer bên trong cấu trúc FILE, nên ta có thể khai thác được

3. Classic FSOP — Vtable Hijacking (pre-glibc 2.24)

Các bản glibc trước 2.24, không có sự kiểm tra hay xác thực trên con trỏ `vtable`. Nên ta có thể thực hiện khai thác như ý tưởng trên:
* Tạo một cấu trúc `_IO_FILE` giả trên vùng nhớ writable bất kỳ (có thể là heap, BSS)
* Overwrite giá trị con trỏ của `vtable` đến một cấu trúc `_IO_jump_t` giả, thực chất là địa chỉ shellcode hoặc `one_gadget`
* Ta nhét cái khối `FILE` giả này vào danh sách `_IO_list_all` (thông qua việc heap exploit)
* Cuối cùng, gọi `exit()` hoặc `fflush()`, glibc sẽ chạy qua danh sách, gọi đến một con trỏ hàm trong `vtables` (như `__overflow` hoặc `__finish`) giả của mình --> thực thi code

3. House of Orange - `_IO_str_overflow` (glibc 2.23 - 2.24)

Với sự xuất hiện của `_IO_vtable_check()`, kỹ thuật hướng tới khai thác các hàm vtable hợp lệ có sẵn như là `_IO_str_overflow`, gọi đến hàm `_s._allocate_buffer` bên trong khi đáp ứng một số điều kiện. 
```c
if (avail != 0)
    (*fp->_s._allocate_buffer)(new_size);
```

Mà `_s._allocate_buffer` lại nằm đâu đấy trong cấu trúc `_IO_FILE`, không phải ở trong vtable nên tránh được cái vtable check. Bằng cách thay đổi cấu trúc sao cho hàm trỏ tới `system` và set trường `_IO_buf_base` trỏ tới `/bin/sh` thì ta khai thác được
```c
_flags              = 0
_IO_buf_base        = &"/bin/sh"
_s._allocate_buffer = &system
_IO_write_ptr - _IO_write_base  >  _IO_buf_end - _IO_buf_base
```

4. House of Apple

Khi mà vtable check càng ngày được vá lại chặt chẽ hơn, kỹ thuật này tận dụng trường `_wide_data` có sẵn trong cấu trúc `_IO_FILE`. Thay vì là tạo một vtable giả khác, ta sẽ chọn một vtable có sẵn, hợp lệ như là `_IO_wfile_jumps` và khai thác `_wide_data->vtable` để kích hoạt `system()`, bỏ qua sự kiểm tra của vtable


___

docs:

https://www.youtube.com/watch?v=Y3apP4bInug&t=20s

https://www.youtube.com/watch?v=Tv1Rss5Vqpk

https://www.youtube.com/watch?v=vkUR58xxSFI&t=1563s












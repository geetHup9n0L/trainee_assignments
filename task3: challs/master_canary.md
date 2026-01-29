### Hiểu về pthread trong c:
Được sử dụng trong thư viện C sau:
```c
#include <pthread.h>
```
Ta sẽ đi với những function cơ bản:
```c
pthread thread1;

pthread_create(&thread1, NULL, (void *) thread_routine, NULL);

pthread_join(thread1, NULL); 
```
Code logic:

Low-level logic:

___ 
**Tài liệu:**

https://www.youtube.com/watch?v=ldJ8WGZVXZk

https://unix.stackexchange.com/questions/528424/are-stack-canaries-shared-via-threads

**Notes:**
Thread Control Block (TCB):
```
Hoạt động ở tầng kernel, và quản lý thông tin các threads 
```
Thread Local Storage (TLS):
```
Vùng nhớ riêng biệt cho mỗi thread
```

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
___ 
**Tài liệu:**

https://www.youtube.com/watch?v=ldJ8WGZVXZk

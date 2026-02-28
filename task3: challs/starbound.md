Thông tin file:

```c
└─$ file starbound
starbound: ELF 32-bit LSB executable, Intel i386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=5a960d92ab1e8594d377bd96eb6ea49980f412a9, not stripped
```
```c
└─$ checksec --file=starbound
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   RW-RUNPATH   151 Symbols  Yes   4               8               starbound
```

Để chạy được file, ta dùng patchelf:
```
└─$ ls                                
libcrypto.so.1.0.0  starbound
```
```
└─$ patchelf --set-rpath . ./starbound
```

Output file:

<img width="821" height="580" alt="image" src="https://github.com/user-attachments/assets/8a90a8bb-dfde-476e-8570-54982f7805e1" />

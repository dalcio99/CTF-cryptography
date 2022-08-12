#!/usr/bin/python

# Disclaimer: implementation of Pollard's algorithm taken from https://www.geeksforgeeks.org/pollard-p-1-algorithm/ 
# notice that using pow() in line 15 is much more efficient than 'a**i % n'


from binascii import hexlify
import math
import os
import sys

def pollard(n):  # returns a non trivial factor of a number which is product of primes p_i such that p_i are smooth
    a = 2
    i = 2
    while(True):
        a = pow(a,i,n)
        d = math.gcd((a-1), n)
        if (d > 1):
            return d
            break
        i += 1


n = 0x7830a3849bf356191195c223a318262c0f8c273ce9364066d0427352e338246d56d3c291699fc19300ae96fb591810ac26bb223aca862d6cec2286233c629a22330bd057c12c6e7226e855e23de87e56718bdd2fd9e6c0c8640c31c69becb464d527f73c882a3a15092f2a1ab07910e29398382abfd2ea32aedc0d51159bb3017f50ecc3129016275b328f8a69697bab3081f60fcd403840658452195b4e43eca3694407366d761c1921ea958b8d7b476fe33c00e38de1f9351baba57024768e3ae9289cd24aa7076d5b9928868df2f796ade2554594df52df052f3fde169bc29c32f159560601bf0fcb9bdde7f66b735248f3e295630795788090fc5eb86055

p = pollard(n)

q = n // p

phi = (p-1)*(q-1)

e = 0x10001

d = pow(e, -1, phi)

c = 0x2f67dba995b03c589b96a9a304f6087f006f4496952ce717db04ea92f82bb00d8126ed10393a7dc7d5c5796dd3053777d60c13423c3e448c19f9d0ac234d877d852f9588df85693f1db9b14fa5dfa28808dd9202bbdf9aa88de9b871c21316761ce01f3f4bf3309af212739b112e4364fb567812b40e6b70ae0306b9de50910bb14d26e26822fff38afedfc560aa3aa8077f5447eef1e47a358a8cf5d7eab7d1dd20420c8b62e43f83a21639cf4497de3091349a5c66fab6d435db39ab50c5882cef096b00b9aad6d62adf08b40778a51f0b981e5c9c7a08142447cd513ed8c40bc299b3656abb8c19f825960c0ef7d9d24e3974d094fe5ad8c4cad4814869a7

hex_flag = hex(pow(c,d,n))
temp = bytes.fromhex(hex_flag[2:]) 
ascii_flag = temp.decode("ASCII")

print(ascii_flag)

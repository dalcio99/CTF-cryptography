# picoCTF2019
# Easy1 

cyph= "UFJKXQZQUNB"
cyph_list = []

key = "SOLVECRYPTO"
key_list = []

plain_list = []

for c in cyph:
   cyph_list.append(ord(c) - 65)

for c in key:
   key_list.append(ord(c) - 65)

for i in range(0, len(cyph_list)):
    plain_list.append((cyph_list[i] - key_list[i] ) % 26)

plain = ""

for i in range(0, len(cyph_list)):
    plain = plain + chr(plain_list[i]+65)

print(plain)

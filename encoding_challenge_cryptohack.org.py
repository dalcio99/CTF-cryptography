# cryptohack.org
# CODING CHALLENGE
# --------------------------------------------------------------------
import string
from pwn import *
import json
import base64
import Crypto.Util.number
import codecs

def json_recv():
    line = r.recvline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    r.sendline(request)

def decode(json):
    if json["type"] == "hex":
        buff = bytes.fromhex(json["encoded"])
        dec = buff.decode("ASCII")
    elif json["type"] == "base64":
        buff = base64.b64decode(json["encoded"])
        dec = buff.decode("ASCII")
    elif json["type"] == "bigint":
        x = json["encoded"]
        n = int(x,0)
        buff = Crypto.Util.number.long_to_bytes(n)
        dec = buff.decode("ASCII")
    elif json["type"] == "utf-8":
        dec = ''
        for c in json["encoded"]:
            dec += chr(c)
    elif json["type"] == "rot13":
        dec = codecs.decode(json["encoded"],"rot-13")
    return dec
        

r = remote('socket.cryptohack.org', 13377, level = 'debug')

for i in range(101):
    rec = json_recv()
    to_send = {"decoded": decode(rec)}
    json_send(to_send)

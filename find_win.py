#!/bin/python
from pwn import *

logging.disable(logging.CRITICAL)

for i in range(32):
    binary = "./bins/bin-"+str(i)
    e = ELF(binary)
    try:
        print(binary + " " + str(e.sym['win']))
    except:
        print(binary + " No Win!")

# this is a dumb way of doing this, just testing an idea

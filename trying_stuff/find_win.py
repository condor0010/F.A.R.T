#!/bin/python
from pwn import *
import os

logging.disable(logging.CRITICAL)

def winnable_binaries():
    path = './bins/'
    out = []
    for binary in os.listdir(path):
        binary = path + binary
        try:
            e = ELF(binary)
        except:
            e = ''
        try:
            temp = (e.sym['win'])
            out.append(binary)
        except:
            temp = ("No Win!")
    return out

for binary in winnable_binaries():
    print(binary)

import os
from pwn import *
from fart import *
from time import sleep

# make pwntools shut up!!!
logging.getLogger('pwnlib').setLevel(logging.WARNING)

path = './bins3/'
for binary in os.listdir(path):
    binary = path + binary
    print(binary+":")
    
    f_anal = analyze(binary)
    f_rop = our_rop(f_anal)
    
    print(f_rop.ss())


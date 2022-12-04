import os
from pwn import *
from fart import *
from time import sleep

# make pwntools shut up!!!
logging.getLogger('pwnlib').setLevel(logging.WARNING)

path = './bins3/'
for binary in os.listdir(path):
    print(binary+":")
    
    a = analyze(path + binary)
    r  = our_rop(a)
    
    print(r.fill_reg('rsi', b'/bin/sh\0'))

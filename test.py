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
    
    print("RDI ", r.pop_reg('rdi'))
    print("RSI ", r.pop_reg('rsi'))
    print("RDX ", r.pop_reg('rdx'))

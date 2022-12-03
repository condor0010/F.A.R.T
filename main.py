import os
from pwn import *
from fart import *
from time import sleep

# make pwntools shut up!!!
logging.getLogger('pwnlib').setLevel(logging.WARNING)

path = './bins/'
args = ['rax', 'rdi', 'rsi', 'rdx', 'r10', 'r8', 'r9']
for binary in os.listdir(path):
    #thingy = our_rop(path + binary)
    analizer = analyze(path + binary)
    print(binary+":")
    print(analizer.has_leak()) 

    '''
    print("    simple check")
    for arg in args:
        print("        {} {}".format(arg, thingy.simple_pop(arg)))

    print("    other check")
    for arg in args:
        print("        {} {}".format(arg, thingy.other_pop(arg)))
    '''


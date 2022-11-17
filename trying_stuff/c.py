from pwn import *
elf = ELF('../bins/bin-21')

# see if usefull functions are on the symbol table
has_gets = 'gets' in elf.symbols
has_win  = 'win' in elf.symbols

if has_gets and has_win:
    print("yay")

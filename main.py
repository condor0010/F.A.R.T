'''
* Return-to-Win
* Return-to-System
Return-to-Execve
Return-to-Syscall
Return-to-Libc (OneGadget)
ROP Write Primitive
Format Strings Stack Leak
Format Strings Libc Leak
Format Strings Write Primitive
Format Strings GOT Overwrite
'''
from auto_exploit_analyzer import *

path = './bins/'
for binary in os.listdir(path):
    print(binary+":")

    analyze(path + binary)
    
    print("    Has /bin/bash ", has_binsh())
    print("    Has flag.txt  ", has_flagtxt())
    print("    Has gets      ", has_gets())
    print("    Has win       ", has_win())
    print("    Has system    ", has_system())
    print("    Has printf    ", has_printf())
    print("    Has overflow  ", has_buffoverflow())
    print("    Has rop       ", has_rop())
    print("    Has syscall   ", has_syscall())
    print("    Has format    ", has_format())

'''
    if has_win():
        print("ret2win")
    if has_rop():
        print("rop is shoehorned in")
    if has_binsh():
        print("ret2system")
'''  


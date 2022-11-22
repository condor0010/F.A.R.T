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
    analyzer = analyze(path + binary)
    print(binary+":")
    #print(analyzer.test())
    print("    Has /bin/bash ", analyzer.has_binsh())
    print("    Has flag.txt  ", analyzer.has_flagtxt())
    print("    Has gets      ", analyzer.has_gets())
    print("    Has win       ", analyzer.has_win())
    print("    Has system    ", analyzer.has_system())
    print("    Has printf    ", analyzer.has_printf())
    print("    Has overflow  ", analyzer.has_buffoverflow())
    print("    Has rop       ", analyzer.has_rop())
    print("    Has syscall   ", analyzer.has_syscall())
    print("    Has format    ", analyzer.has_format())

'''
    if has_win():
        print("ret2win")
    if has_rop():
        print("rop is shoehorned in")
    if has_binsh():
        print("ret2system")
'''  


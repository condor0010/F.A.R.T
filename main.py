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
import os
from pwn import *
from auto_exploit_analyzer import analyze

path = './bins/'
for binary in os.listdir(path):
    analyzer = analyze(path + binary)
    print(binary+":")
    print("    Has /bin/bash ", analyzer.has_binsh())
    print("    Has flag.txt  ", analyzer.has_flagtxt())
    print("    Has gets      ", analyzer.has_gets())
    print("    Has win       ", analyzer.has_win())
    print("    Has system    ", analyzer.has_system())
    print("    Has printf    ", analyzer.has_printf())
    #print("    Has overflow  ", analyzer.has_buffoverflow())
    print("    Has rop       ", analyzer.has_rop())
    print("    Has syscall   ", analyzer.has_syscall())
    print("    Has format    ", analyzer.has_format())
    print("    Has execve    ", analyzer.has_execve())
    print("        /bin/sh   ", analyzer.get_binsh())
    print("        flag.txt  ", analyzer.get_flagtxt())
    print("        win       ", analyzer.get_win())


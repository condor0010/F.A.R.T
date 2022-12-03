import os
from pwn import *
from fart import *

#path = './bins3/'
#for binary in os.listdir(path):
thingy = our_rop('./bins3/bin-ret2execve-12')

args = ['rax', 'rdi', 'rsi', 'rdx', 'r10', 'r8', 'r9']
print("simple check")
for arg in args:
    print("    {} {}".format(arg, thingy.simple_pop(arg)))

print("other check")
for arg in args:
    print("    {} {}".format(arg, thingy.other_pop(arg)))



'''
print("    Has /bin/bash    ", analyzer.has_binsh())
print("    Has flag.txt     ", analyzer.has_flagtxt())
print("    Has cat flag.txt ", analyzer.has_catflagtxt())
print("    Has gets         ", analyzer.has_gets())
print("    Has win          ", analyzer.has_win())
print("    Has system       ", analyzer.has_system())
print("    Has printf       ", analyzer.has_printf())
print("    Has rop          ", analyzer.has_rop())
print("    Has syscall      ", analyzer.has_syscall())
print("    Has format       ", analyzer.has_format())
print("    Has execve       ", analyzer.has_execve())
print("        /bin/sh      ", analyzer.get_binsh())
print("        cat flag.txt ", analyzer.get_catflagtxt())
print("        flag.txt     ", analyzer.get_flagtxt())
print("        win          ", analyzer.get_win())
'''

import os, sys
from pwn import *
from fart import *
from time import sleep
logging.getLogger('pwnlib').setLevel(logging.WARNING)

def main():
    path = 'bins2/'
    for binary in os.listdir(path):
        binary = path + binary 
        #print(binary+":")
        
        f_anal = analyze(binary)
        '''
        print("    Has /bin/bash    ", f_anal.has_binsh())
        print("    Has flag.txt     ", f_anal.has_flagtxt())
        print("    Has cat flag.txt ", f_anal.has_catflagtxt())
        print("    Has gets         ", f_anal.has_gets())
        print("    Has win          ", f_anal.has_win())
        print("    Has system       ", f_anal.has_system())
        print("    Has printf       ", f_anal.has_printf())
        print("    Has rop          ", f_anal.has_rop())
        print("    Has syscall      ", f_anal.has_syscall())
        print("    Has format       ", f_anal.has_format())
        print("    Has execve       ", f_anal.has_execve())
        print("        /bin/sh      ", f_anal.get_binsh())
        print("        cat flag.txt ", f_anal.get_catflagtxt())
        print("        flag.txt     ", f_anal.get_flagtxt())
        print("        win          ", f_anal.get_win())
        '''
        if(f_anal.win_has_args()):
            print(binary)
            print(f_anal.get_win_arg())



main()

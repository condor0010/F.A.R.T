#!/bin/pythoni
from pwn import *
import sys
from fart import *

def check_vuln_type(binary):
    
    if binary.has_binsh():
        print("Has binsh")
    if binary.has_flagtxt():
        print("Has flag.txt")
    if binary.has_catflagtxt():
        print("Has cat flag")
    if binary.has_gets():
        print("Has gets")
    if binary.has_win():
        print("Has win")
    if binary.has_system():
        print("Has system")
    if binary.has_printf():
        print("Has printf")
    if binary.has_syscall():
        print("Has syscall")
    if binary.has_format():
        print("Has format")
    if binary.has_execve():
        print("Has execve")
    if binary.has_rop():
        print("Has ROP")

if __name__ == "__main__":
    binary = args.BIN

    analyze = Analyze(binary)
    check_vuln_type(analyze)


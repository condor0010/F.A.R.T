#!/bin/pythoni
from pwn import *
import sys
from fart import *
import FMT
import ROP


logging.getLogger('pwnlib').setLevel(logging.WARNING)

def check_vuln_type(binary):
    properties = {} 
    if binary.has_binsh():
        print("[+]String of interest: 'binsh' present")
        properties["binsh"] = True
    if binary.has_flagtxt():
        print("[+] String of interest: 'flag.txt' present")
        properties["flag"] = True
    if binary.has_catflagtxt():
        print("[+] String of interest: 'cat flag.txt' present")
        properties["cat"] = True
    if binary.has_gets():
        print("[+] Gets present")
        properties["gets"] = True
    if binary.has_win():
        print("[+] Win function present")
        properties["win"] = True
    if binary.has_system():
        print("[+] System function present")
        properties["system"] = True
    if binary.has_printf():
        print("[+] Printf function present")
        properties["printf"] = True
    if binary.has_syscall():
        print("[+] Syscall function present")
        properties["syscall"] = True
    if binary.has_format():
        print("[+] Possible format string bug")
        properties["format"] = True
    if binary.has_execve():
        print("[+] Execve function present")
        properties["execve"] = True
    if binary.has_rop():
        print("[+] Possible ROP conditions")
        properties["rop"] = True

    return properties



if __name__ == "__main__":
    binary = args.BIN

    analyze = Analyze(binary)
    properties = check_vuln_type(analyze)

    #TODO: Create a function that determines what to do given properties
    if properties["win"]:
        #TODO: Move this stuff to ROP
        #wtf = Get2overflow(binary)
        #offset = wtf.buf()
        rop = ROP.ROP(binary, properties)
        rop.ret2win()

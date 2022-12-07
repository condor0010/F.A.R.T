import re
import json
import r2pipe
import logging
from pwn import *
from Print import *

logging.getLogger('pwnlib').setLevel(logging.WARNING)
logging.disable(logging.CRITICAL)

class Analyze:
    def __init__(self, binary, bin_hash):
        self.binary = binary
        self.bin_hash = bin_hash
        self.elf  = ELF(binary)
        self.libc = ELF('/opt/libc.so.6')
        self.bin_name = binary.split("/")[-1]

        # r2pipe setup
        self.r2 = r2pipe.open(self.binary, flags=['-2']) # open binary
        self.r2.cmd('e scr.color=1')
        self.r2.cmd('aaa') # analyze binary
        self.izz = json.loads(self.r2.cmd('izj')) # returns json relating to strings
        self.afl = json.loads(self.r2.cmd('aflj')) # returns json relating to functions
        
        # see what is in the binary
        self.strings = [i['string'] for i in self.izz if 'string' in i] # returns list of strings
        self.functions = [i['name'] for i in self.afl if 'name' in i] # returns list of functions
        
        # get addrs of what is in the binary
        self.string_addrs = dict(zip(self.strings, [i['vaddr'] for i in self.izz if 'string' in i]))
        self.function_addrs = dict(zip(self.functions, [i['offset'] for i in self.afl if 'name' in i]))


        # TODO: rename hbsh to inserted_binsh
        self.hbsh = False
        
    # has stuff
    def has_leak_string(self):
        for i in self.strings:
            if "Leak" in i:
                return True
        return False
    
    # TODO: rename hbsh to inserted_binsh
    def has_binsh(self):
        if self.hbsh:
            return self.hbsh
        for i in self.strings:
            if "/bin/sh" in i:
                return True
        return False

    def has_flagtxt(self):
        for i in self.strings:
            if "flag.txt" in i:
                return True
        return False

    def has_catflagtxt(self):
        for i in self.strings:
            if "cat flag.txt" in i: 
                return True
        return False

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
   
    # Send %p
    def has_format(self):
        return not self.has_win() and not self.has_rop()
    
    def has_execve(self):
        return 'sym.imp.execve' in self.functions
   
    # DEPRICATED! Use has_leak to determine if the input is vulnerable
    # to format string bugs. If not, then it should be vulnerable to BOF
    def has_rop(self):
        return any((match := re.compile(r'gadget*').match(i)) for i in self.functions)

    def has_canary(self):
        return "true" in self.r2.cmd('iI~canary')

    def has_nx(self):
        return 'true' in self.r2.cmd('iI~NX')

    def has_putchar(self):
        return 'sym.imp.putchar' in self.functions

    def win_has_args(self):
        if self.has_win():
            return "" != self.r2.cmd("pdf @ sym.win | grep cmp")
        return False

    def vuln_has_cmp(self):
        if self.has_win():
            return "" != self.r2.cmd("pdf @ sym.vuln | grep cmp")
        return False

    # get stuff
    def get_binsh(self):
        if self.has_binsh():
            return next(self.elf.search(b"/bin/sh\0"))
        else:
            return None

    def get_flagtxt(self):
        if self.has_flagtxt():
            return next(self.elf.search(b"flag.txt\0"))
        else:
            return None

    def get_catflagtxt(self):
        if self.has_catflagtxt():
            return next(self.elf.search(b"cat flag.txt\0"))
        else:
            return None
    
    def get_win(self):
        return self.function_addrs['sym.win']
   
    def get_win_arg(self):
        return self.r2.cmd('pdf @ sym.win | grep cmp | awk \'{print $NF}\'')

    def get_vuln(self):
        return self.function_addrs['sym.vuln']

    def get_fini(self):
        return self.function_addrs["sym._fini"]

    def get_vuln_args(self):
        if self.has_win():
            return int(self.r2.cmd("pdf @ sym.vuln | grep cmp | awk \'{print $NF}\'"))
        return None
 
    def libc_printf(self, libc_fcn):
        return '' != self.r2.cmd('pdf @ sym.vuln~reloc.printf')

    def libc_puts(self):
        return '' != self.r2.cmd('pdf @ sym.vuln~reloc.puts')

    #TODO make less shitty, potential edge casess
    def find_leaked_function(self):
        return self.r2.cmd('pdf @ sym.vuln~reloc. | awk -F \'reloc\' \'{print $NF}\' | awk \'{print $1}\'').strip('.')[:-2]

    def has_leak(self):
        if not self.has_leak_string():
            p = process(self.binary)
            p.sendline(b"%1p")
            try:
                p.recvuntil(b"<<<")
                return "0x" in p.recvline().decode("utf-8")
            except EOFError as e:
                return False

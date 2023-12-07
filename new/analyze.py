import re
import json
import rzpipe
import logging
from pwn import *
#from Print import *

class Analyze:
    def __init__(self, binary):
        self.binary = binary
        #self.bin_hash = bin_hash
        self.elf  = ELF(binary)
        self.libc = ELF('../docker/libc/libc.so.6')
        self.bin_name = binary.split("/")[-1]

        # r2pipe setup
        self.rz = rzpipe.open(self.binary, flags=['-2']) # open binary, disable stderr
        self.rz.cmd('e scr.color=0')
        self.rz.cmd('aaa') # analyze binary
        self.izz = self.rz.cmdj('izj') # returns json relating to strings
        self.afl = self.rz.cmdj('aflj') # returns json relating to functions
        
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
        return "true" in self.rz.cmd('iI~canary')

    def has_nx(self):
        return 'true' in self.rz.cmd('iI~NX')

    def has_putchar(self):
        return 'sym.imp.putchar' in self.functions

    def win_has_args(self):
        if self.has_win():
            return "" != self.rz.cmd("pdf @ sym.win ~ cmp")
        return False

    def vuln_has_cmp(self):
        if self.has_win():
            return "" != self.rz.cmd("pdf @ sym.vuln ~ cmp")
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
            return next(self.elf.search(b"cat flag.txt"))
        else:
            return None
    
    def get_win(self):
        return self.function_addrs['sym.win']
   
    def get_win_arg(self):
        return self.rz.cmdj('pdfj @ sym.win')

    def get_vuln(self):
        return self.function_addrs['sym.vuln']

    def get_fini(self):
        return self.function_addrs["sym._fini"]

    def get_vuln_args(self):
        if self.has_win():
            return self.rz.cmdj("pdfj @ sym.vuln")
        return None
 
    def libc_printf(self, libc_fcn):
        return '' != self.rz.cmd('pdf @ sym.vuln~reloc.printf')

    def libc_puts(self):
        return '' != self.rz.cmd('pdf @ sym.vuln~reloc.puts')

    #TODO make less shitty, potential edge casess
    def find_leaked_function(self):
        return self.rz.cmd('pdf @ sym.vuln~reloc. | awk -F \'reloc\' \'{print $NF}\' | awk \'{print $1}\'').strip('.')[:-2]

    def has_leak(self):
        if not self.has_leak_string():
            p = process(self.binary)
            p.sendline(b"%1p")
            try:
                p.recvuntil(b"<<<")
                return "0x" in p.recvline().decode("utf-8")
            except EOFError as e:
                return False

# grep def analyze.py | sed "s/(.*)/()/g;s/://g;s/ *def /    print ( analyze./g;s/$/ )/g" | grep -v "__"  | awk '{print "    "$1" "$2" \""$3" \" + str("$3") "$4}'
if __name__ == "__main__":
    import sys
    binary = sys.argv[1]
    analyze = Analyze(binary)
    print ( "analyze.has_leak_string() " + str(analyze.has_leak_string()) )
    print ( "analyze.has_binsh() " + str(analyze.has_binsh()) )
    print ( "analyze.has_flagtxt() " + str(analyze.has_flagtxt()) )
    print ( "analyze.has_catflagtxt() " + str(analyze.has_catflagtxt()) )
    print ( "analyze.has_gets() " + str(analyze.has_gets()) )
    print ( "analyze.has_win() " + str(analyze.has_win()) )
    print ( "analyze.has_system() " + str(analyze.has_system()) )
    print ( "analyze.has_printf() " + str(analyze.has_printf()) )
    print ( "analyze.has_syscall() " + str(analyze.has_syscall()) )
    print ( "analyze.has_format() " + str(analyze.has_format()) )
    print ( "analyze.has_execve() " + str(analyze.has_execve()) )
    print ( "analyze.has_rop() " + str(analyze.has_rop()) )
    print ( "analyze.has_canary() " + str(analyze.has_canary()) )
    print ( "analyze.has_nx() " + str(analyze.has_nx()) )
    print ( "analyze.has_putchar() " + str(analyze.has_putchar()) )
    print ( "analyze.win_has_args() " + str(analyze.win_has_args()) )
    print ( "analyze.vuln_has_cmp() " + str(analyze.vuln_has_cmp()) )
    print ( "analyze.get_binsh() " + str(analyze.get_binsh()) )
    print ( "analyze.get_flagtxt() " + str(analyze.get_flagtxt()) )
    print ( "analyze.get_catflagtxt() " + str(analyze.get_catflagtxt()) )
    print ( "analyze.get_win() " + str(analyze.get_win()) )
    print ( "analyze.get_win_arg() " + str(analyze.get_win_arg()) )
    print ( "analyze.get_vuln() " + str(analyze.get_vuln()) )
    print ( "analyze.get_fini() " + str(analyze.get_fini()) )
    print ( "analyze.get_vuln_args() " + str(analyze.get_vuln_args()) )
    print ( "analyze.libc_printf() " + str(analyze.libc_printf()) )
    print ( "analyze.libc_puts() " + str(analyze.libc_puts()) )
    print ( "analyze.find_leaked_function() " + str(analyze.find_leaked_function()) )
    print ( "analyze.has_leak() " + str(analyze.has_leak()) )

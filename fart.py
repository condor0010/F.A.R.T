'''
* Return-to-Win
* Return-to-System
* Return-to-Execve
* Return-to-Syscall
Return-to-Libc (OneGadget)
ROP Write Primitive
* Format Strings Stack Leak
Format Strings Libc Leak
Format Strings Write Primitive
Format Strings GOT Overwrite
'''

import re
import json
import angr
import r2pipe

# Identify solution set from binary.
# i.e. write a tool that's sole purpose is identifying which techniques we need to use.

class analyze:
    def __init__(s, binary):
        # misc
        #s.fastcall = []

        # angr setup
        
        
        # r2pipe setup
        s.binary = binary
        s.r2 = r2pipe.open(binary) # open binary
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

    def test(s):
        print(s.string_addrs)
        print(s.function_addrs)


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
    
    #for i in s.izz:
    #    return i['vaddr'] if (i['string'] == '/bin/sh') else next
    
    def get_binsh(s):
        try:
            return s.string_addrs['/bin/sh']
        except:
            return None
    def get_flagtxt(s):
        try:
            return s.string_addrs['flag.txt']
        except:
            return None 
    def get_catflagtxt(s):
        try:
            return s.string_addrs['/bin/sh']
        except:
            return None
    def get_win(s):
        try:
            return s.function_addrs['sym.win']
        except:
            return None
    def get_vuln(s):
        try:
            return s.function_addrs['sym.vuln']
        except:
            return None
    



    #def has_buffoverflow(s):
    #    io = process(s.binary)
    #    io.sendline(b'A'*2048)
    #    try:
    #        io.recvline()
    #    except:
    #        return True
    #    return False

    #def has_leak(s):
    #    io = process(s.binary)
    #    io.sendline(b'%1p')
    #    try:
    #        return '0x' in io.recvline().encode('utf-8')
    #    except:
    #        return True
    #def test_ret(s):
    #    print(r2.cmd('/R/q pop [er][abcds891][ipx012345]'))

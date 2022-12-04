from pwn import *

class FMT:
    def __init__(self, analysis):
        self.analysis = analysis
        self.filename = analysis.binary
        self.e = ELF(self.filename)
    
    def build_exploit(self):
        pass

    def stack_leak(self):
        
        pass

    def libc_leak(self):
        pass

    def got_overwrite(self):
        pass

    def supporting_functions_here(self):
        print("example support function")


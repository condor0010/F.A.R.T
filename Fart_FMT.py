from pwn import *

class FMT:
    def __init__(self, analysis, properties):
        self.analysis = analysis
        self.filename = analysis.binary
        self.properties = properties
        self.e = ELF(self.filename)

    def stack_leak(self):
        pass

    def libc_leak(self):
        pass

    def got_overwrite(self):
        pass

    def supporting_functions_here(self):
        print("example support function")


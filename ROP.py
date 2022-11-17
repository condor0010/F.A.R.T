
class ROP:
    def __init__(self, filename, properties):
        self.filename = filename
        self.properties = properties

    # Smash stack and change return address to win()
    def ret2win(self, vuln_input, padding):
		# Craft the exploit
        self.exploit = b'a'*padding + p64(self.elf.sym['win'])
        self.send_rop(vuln_input)

    def ret2system(self):
        pass

    def ret2execve(self):
        pass

    def ret2syscall(self):
        pass

    def supporting_functions_here(self):
        print("example support function")

    # send_rop()?
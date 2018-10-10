### challenge
```txt
This level takes a look at converting strings to little endian integers.

This level is at /opt/protostar/bin/net0
```

### net0.c
```c
#include "../common/common.c"

#define NAME "net0"
#define UID 999
#define GID 999
#define PORT 2999

void run()
{
  unsigned int i;
  unsigned int wanted;

  wanted = random();

  printf("Please send '%d' as a little endian 32bit int\n", wanted);

  if(fread(&i, sizeof(i), 1, stdin) == NULL) {
      errx(1, ":(\n");
  }

  if(i == wanted) {
      printf("Thank you sir/madam\n");
  } else {
      printf("I'm sorry, you sent %d instead\n", i);
  }
}

int main(int argc, char **argv, char **envp)
{
  int fd;
  char *username;

  /* Run the process as a daemon */
  background_process(NAME, UID, GID); 
  
  /* Wait for socket activity and return */
  fd = serve_forever(PORT);

  /* Set the client socket to STDIN, STDOUT, and STDERR */
  set_io(fd);

  /* Don't do this :> */
  srandom(time(NULL));

  run();
}
```

### test run
```txt
user@protostar:/opt/protostar/bin$ python
Python 2.6.6 (r266:84292, Dec 27 2010, 00:02:40) 
[GCC 4.4.5] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> import socket, struct
>>> 
>>> sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
>>> sock.connect(('127.0.0.1', 2999))
>>> data = sock.recv(1024)
>>> num = int(data[13:23])
>>> sock.send(struct.pack("<I", num))
4
>>> print sock.recv(1024)
Thank you sir/madam

>>> sock.close()
>>> 
```

### solution 1
```txt
user@protostar:/opt/protostar/bin$ python -c 'import socket, struct;sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM);sock.connect(("127.0.0.1", 2999));data = sock.recv(1024);num = int(data[13:23]);sock.send(struct.pack("<I", num));print sock.recv(1024);sock.close()'
Thank you sir/madam

```
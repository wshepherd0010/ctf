# Pwnable.kr FD
Mommy! what is a file descriptor in Linux?

* try to play the wargame your self but if you are ABSOLUTE beginner, follow this tutorial link: https://www.youtube.com/watch?v=blAxTfcW9VU

ssh fd@pwnable.kr -p2222 (pw:guest)

# Files
```sh
fd@ubuntu:~$ ls
fd  fd.c  flag
fd@ubuntu:~$ cat fd.c
```
# fd.c
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
	if(argc<2){
		printf("pass argv[1] a number\n");
		return 0;
	}
	int fd = atoi( argv[1] ) - 0x1234;
	int len = 0;
	len = read(fd, buf, 32);
	if(!strcmp("LETMEWIN\n", buf)){
		printf("good job :)\n");
		system("/bin/cat flag");
		exit(0);
	}
	printf("learn about Linux file IO\n");
	return 0;

}
```

# File Security Settings
```sh
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial
```

# Descriptor Size + 1
File descriptor is argument 1 minus 0x1234. Add 0x1234 + 1 = 4661...

# Flag
Kinda gay..

```sh
fd@ubuntu:~$ ./fd 4661
LETMEWIN
good job :)
mommy! I think I know what a file descriptor is!!
```
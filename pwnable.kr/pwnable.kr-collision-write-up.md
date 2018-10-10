# Pwnable.kr Collision
Daddy told me about cool MD5 hash collision today.
I wanna do something like that too!

ssh col@pwnable.kr -p2222 (pw:guest)

```c
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
        int* ip = (int*)p;
        int i;
        int res=0;
        for(i=0; i<5; i++){
                res += ip[i];
        }
        return res;
}
int main(int argc, char* argv[]){
        if(argc<2){
                printf("usage : %s [passcode]\n", argv[0]);
                return 0;
        }
        if(strlen(argv[1]) != 20){
                printf("passcode length should be 20 bytes\n");
                return 0;
        }

        if(hashcode == check_password( argv[1] )){
                system("/bin/cat flag");
                return 0;
        }
        else
                printf("wrong passcode.\n");
        return 0;
}
```
# char* argv[] is the argument passed to the col binary, it's an array of char pointers. The first argument must be 20 characters long.
```c
if(strlen(argv[1]) != 20){
```

# The 20 character argument is passed to check_password as a char pointer. The first line of code type casts the char pointer to an int pointer.
```c
int* ip = (int*)p;
```
# Then the int res variable is set to 0. The int ip pointer (the char pointer type casted), is iterated through a total of 5 times, each iteration adding the integer value to the res variable. 
```c
int i;
int res=0;
for(i=0; i<5; i++){
        res += ip[i];
}
```
# To break that down, it loops 5 times, and the int value from the int pointer is added to a total sum, which is stored in res. The loop completes, and the value of res is returned. The int res value is compared to the hashcode (which is in hexidecimal).
```c
unsigned long hashcode = 0x21DD09EC;
```
# The hashcode divided by 5, plus the remainder of 0x4.
```sh
(gdb) print /x 0x21DD09EC / 0x5
$1 = 0x6c5cec8
(gdb) print /x 0x6c5cec8 * 0x5
$2 = 0x21dd09e8
(gdb) print /x 0x21DD09EC - 0x21dd09e8
$3 = 0x4
(gdb) print /x 0x6c5cec8 + 0x4
$4 = 0x6c5cecc
```
# Pass the bytes in reverse order...
```sh
col@ubuntu:~$ ./col `python -c 'import struct;print struct.pack("<I",0x6c5cec8)*4+struct.pack("<I",0x6c5cecc)'`
daddy! I just managed to create a hash collision :)
col@ubuntu:~$
```
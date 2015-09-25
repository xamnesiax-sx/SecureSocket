from binascii import hexlify, unhexlify
from definitions import *
from cryptolib import *
import socket
import re

class socket_wrapper(object):

    def __init__(self, sock=None):

        # General
        self._options = Socket_options
        self._option_list = []

        self._socket = socket.socket()

        if sock != None:
            self._socket = sock

        self.proto = proto()

    def __getattr__(self, name):
        return getattr(self._socket, name)

    def flush_options(self):
        self._options = Socket_options

    def set_option(self, option, value):
        if option in self._options:
            self._options = value
            self.verified_options = False

            return True

        return False

    def get_option(self, option):
        if option in self._options:
            return self._options

        return None

    def save_options(self, name):
        if name not in self._option_list:
            self._option_list[name] = self._options
            self.flush_options()

    def load_options(self, name, backup=False):
        if name in self._option_list:
            if backup:
                self._option_list['_'] = self._options

            self._options = self._option_list[name]

    def accept(self):
        clientsock, clientinfo = self._socket.accept()
        sock = socket_wrapper(sock=clientsock)

        if self.get_option('handshake_on_connect') is HOC_TRUE:
            sock.handshake()

        return sock, clientinfo

    def connect(self, info):
        a = self._socket.connect(info)

        if self.get_option('handshake_on_connect') is HOC_TRUE:
            b = self.handshake()
            return b

        return a

    def _send(self, data):
        self._socket.send(str(len(data)))
        res = self._socket.recv(1)

        if res is OK:
            r = self._socket.send(data)
        elif res is FAIL:
            raise Exception('Peer could not allocate requested space.')

        return r

    def send(self, data):
        data = self.proto.create_inner(data)

        algorithm = self.get_option('algorithm')

        if algorithm is ALGORITHM_AES:
            key = self.get_option('aes_key')
        elif algorithm is ALGORITHM_RSA:
            key = self.get_option('peer_public_key')

        if algorithm != ALGORITHM_PLAIN:
            data = encrypt(key, data, algorithm)

            if len(data) == 1:
                self._send(self.proto.create_outer(data, signkey=self.get_option('local_sign_key')))
                return

            elif len(data) == 2:
                self._send(self.proto.create_outer(data[0],
                           signkey=self.get_option('local_sign_key'),
                           block=data[1]))

                return

        if self.get_option('sign_level') == SIGN_LEVEL_ALL:
            self._send(self.proto.create_outer(data, signkey=self.get_option('local_sign_key')))
        else:
            self._send(self.proto.create_outer(data))

    def _recv(self):
        data = self._socket.recv(1)
        self._socket.send(str(OK))

        if type(data) is int:
            data = self._socket.recv(data)
            return data

        raise Exception('Preallocation data was not in integer form')

    def recv(self, *p):
        data = self._recv()

        return self.parse_inner(self.proto.parse_outer(data, verifykey=self.get_option('peer_verify_key')))

    def send_recv(self, data):
        self.send(data)
        return self.recv()

    def close(self):
        pass

    def handshake(self):
        pass


class proto(object):

    def __init__(self):
        self.crypto = Crypto()

    @staticmethod
    def has_section(name, data, ret=False, headers=False):
        start = D_HEAD_BEGIN % name.upper()
        end = D_HEAD_END % name.upper()

        d = re.findall('%s(.*?)%s' % (start, end), data, re.DOTALL)

        if len(d) != 0:
            if ret:
                if headers:
                    d[0] = '%s%s%s' % (start, d[0], end)

                return d[0]

            return True

        if ret:
            return ''
        
        return False

    def get_section(names, data, headers=False):
        r = ''

        if type(names) is str:
            names = [names]

        for name in names:
            if names.index(name) == 0:
                r += self.has_section(name, data, ret=True, headers=headers)
                continue

            r += '\n%s' % self.has_section(name, data, ret=True, headers=headers)

        return r

    @staticmethod
    def create_section(name, data, append=True):
        start = D_HEAD_BEGIN % name.upper()
        end = D_HEAD_END % name.upper()

        section = ''

        if append:
            section += '\n'

        section += '%s%s%s' % (start, data, end)

        return section

    def create_outer(self, data, block=None, signkey=None):
        
        package = self.create_section('data', hexlify(data), append=False)

        if block is not None:
            package += self.create_section('block', hexlify(block))

        if signkey is not None:
            signature = self.crypto.sign(signkey, package)
            package += self.create_section('signature', hexlify(signature))

        return package

    def parse_outer(self, package, verifykey=None):
        r = []

        if self.has_section('signature', package) and verifykey != None:
            signature = self.get_section('signature', package)

            if self.has_section('block', package):
                verify = self.get_section(['data', 'block'], package, headers=True)

            else:
                verify = self.get_section('data', package, headers=True)

            if not self.crypto.verify(verifykey, verify, signature):
                raise Exception('Message failed to verify.')

        r.append(self.get_section('data', package))

        if self.has_section('block', package):
            r.append(self.get_section('block', package))

        return r

    @staticmethod
    def create_inner(data):
        return data

    def parse_inner(data):
        return data

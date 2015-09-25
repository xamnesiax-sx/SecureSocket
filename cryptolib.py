# Note, two types of random lib, remember in case of error.

from Crypto.Signature import PKCS1_v1_5 as PKCS
from Crypto.Random import random as Random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512 as SHA
from Crypto.Cipher import AES
from Crypto import Random as R

from definitions import *

class Crypto(object):

    @staticmethod
    def _rsa_encrypt(k, p):
        return list(k.encrypt(p, 0))

    @staticmethod
    def _rsa_decrypt(k, ct):
        return k.decrypt(ct)

    @staticmethod
    def _aes_encrypt(k, p):
        b = R.new().read(Aes.block_size)
        c = AES.new(k, AES.MODE_CFB, b)
        
        return [c.encrypt(p), b]

    @staticmethod
    def _aes_decrypt(k, ct, b):
        c = AES.new(k, AES.MODE_CFB, b)
        return c.decrypt(ct)

    def encrypt(self, key, data, algorithm):
        if algorithm is ALGORITHM_RSA:
            return self._rsa_encrypt(key, data)

        elif algorithm is ALGORITHM_AES:
            return self._aes_encrypt(key, data)

        else:
            raise Exception('Unknown algorithm.')

    def decrypt(self, key, data, algorithm, block=None):
        if algorithm is ALGORITHM_RSA:
            return self._rsa_decrypt(key, data)

        elif algorithm is ALGORITHM_AES:
            if block != None:
                return self._aes_decrypt(key, data, block)
            
            raise Exception('Algorithm \'AES\' specified, but no block was provided for decryption.')

        else:
            raise Exception('Unknown algorithm.')

    @staticmethod
    def sign(key, data):
        h = SHA.new(data)
        s = PKCS.new(key)

        return s.sign(h)

    @staticmethod
    def verify(key, data, signature):
        h = SHA.new(data)
        v = PKCS.new(key)

        return v.verify(h, signature)

from Crypto.Cipher import AES
from Crypto import Random
import os


class Cryptor:
    __padlen = 0
    def __init__(self, key):
        self.key = key
    
    def __pad(self, s):
        mod = len(s) % AES.block_size
        self.__padlen = AES.block_size - mod if mod else 0
        return s + b'\x00' * self.__padlen
    
    def encrypt(self, s, key):
        s = self.__pad(s)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return bytes([self.__padlen]) + iv + cipher.encrypt(s)

    def decrypt(self, s, key):
        self.__padlen = s[0]
        iv = s[1 : AES.block_size + 1]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        if self.__padlen:
            return cipher.decrypt(s[AES.block_size + 1 : ])[ : -self.__padlen]
        else:
            return cipher.decrypt(s[AES.block_size + 1 : ])
    
    def encrypt_file(self, file_name):
        with open(file_name, 'rb') as fp:
            s = fp.read()
        s = self.encrypt(s, self.key)
        os.rename(file_name, file_name + '.tmp')
        with open(file_name, 'wb') as fp:
            fp.write(s)
        os.remove(file_name + '.tmp')
    
    def decrypt_file(self, file_name):
        with open(file_name, 'rb') as fp:
            s = fp.read()
        s = self.decrypt(s, self.key)
        os.rename(file_name, file_name + '.tmp')
        with open(file_name, 'wb') as fp:
            fp.write(s)
        os.remove(file_name + '.tmp')

if __name__ == '__main__':
    while 1:
        key = input('input your key: ').encode()
        
        try:
            if len(key) != 32:
                raise Exception
        except Exception:
            print('[!]you need a 32 bytes key')
        else:
            break
    cryptor = Cryptor(key)
    cryptor.decrypt_file(r'./test.txt')
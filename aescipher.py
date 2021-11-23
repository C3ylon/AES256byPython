from os import cpu_count, remove, rename
from Crypto.Cipher import AES
import Crypto.Random
from time import time

BUFFSIZE = 1024**3

class Cryptor:
    def __init__(self, key):
        try:
            if type(key) != bytes or len(key) != 32:
                raise Exception
        except:
            print('[!]key should be 32 bytes')
            exit(0)
        else:
            self.key = key
    
    def __gen_filehead(self, align):
        return b'\xe8\xe9\x90\x90\x90\x90\xc3' + bytes([align & 0x0F | 0xC0])

    def encrypt_file(self, filename):
        with open(filename, 'rb') as fr:
            with open(filename + '.tmp', 'wb') as fw:
                fr.seek(0, 2)
                sz = fr.tell()
                fr.seek(0, 0)
                iv = Crypto.Random.new().read(16)
                align = sz & 0x0F
                fw.write(self.__gen_filehead(align) + iv)
                chunks = sz // BUFFSIZE
                if sz % BUFFSIZE:
                    chunks += 1
                while chunks:
                    chunks -= 1
                    buff = fr.read(BUFFSIZE)
                    if chunks == 0 and align:
                        buff = buff + b'\x00' * (16 - align)
                    buff = AES.new(self.key, AES.MODE_CBC, iv).encrypt(buff)
                    fw.write(buff)
                    iv = buff[-16:]
        remove(filename)
        rename(filename + '.tmp', filename)    

    def decrypt_file(self, filename):
        with open(filename, 'rb') as fr:
            buff = fr.read(7)
            if buff != b'\xe8\xe9\x90\x90\x90\x90\xc3':
                return
            with open(filename + '.tmp', 'wb') as fw:
                align = fr.read(1)[0] & 0x0F
                iv = fr.read(16)
                fr.seek(0, 2)
                sz = fr.tell() - 24
                fr.seek(24, 0)
                chunks = sz // BUFFSIZE
                if sz % BUFFSIZE:
                    chunks += 1
                while chunks:
                    chunks -= 1
                    buff = fr.read(BUFFSIZE)
                    tmp = AES.new(self.key, AES.MODE_CBC, iv)
                    iv = buff[-16:]
                    buff = tmp.decrypt(buff)
                    if chunks == 0 and align:
                        fw.write(memoryview(buff[:align - 16]))
                    else:
                        fw.write(buff)
        remove(filename)
        rename(filename + '.tmp', filename)

s=time()
cp =Cryptor(b'\x01\x02\x03\x04' * 8)
cp.decrypt_file('test.txt')
# cp.decrypt_file(r'D:\steam\steamapps\common\BrightMemoryInfinite\BrightMemoryInfinite\Content\Paks\BrightMemoryInfinite-WindowsNoEditor.pak')
e=time()
print(e-s)

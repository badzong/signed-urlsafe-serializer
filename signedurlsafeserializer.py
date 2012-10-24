import hashlib
import string
import random
import base64
import json

try:
    import zlib
except ImportError:
    zlib_available = False
else:
    zlib_available = True


class BadDataError(Exception):
    pass


class SignedURLSafeSerializer(object):
    compressor = None

    def __init__(self, secret, salt_len=4, hash=hashlib.sha256,
        serializer=json):

        self.secret = secret
        self.salt_len = salt_len
        self.hash = hash
        self.set_hash_length()
        self.serializer = serializer

        if zlib_available:
            self.compressor = zlib

    def set_hash_length(self):
        self.hash_len = len(self.digest('foo', 'bar'))

    def salt(self):
        s = ''
        for i in range(self.salt_len):
            s += random.choice(string.letters + string.digits)

        return s

    def dump(self, data):
        dump = self.serializer.dumps(data)

        if self.compressor:
            dump = self.compressor.compress(dump, 9)

        dump = base64.urlsafe_b64encode(dump).replace('=', '+')

        return dump.rstrip('=')

    def load(self, dump):
        data = base64.urlsafe_b64decode(dump.replace('+', '='))

        if self.compressor:
            data = self.compressor.decompress(data)

        data = self.serializer.loads(data)

        return data

    def digest(self, data, salt):
        auth_message = ''.join((self.secret, data, salt))
        md = self.hash()
        md.update(auth_message)
        digest = base64.urlsafe_b64encode(md.digest()).rstrip('=')

        return digest

    def pack(self, data):
        salt = self.salt()
        dump = self.dump(data)
        digest = self.digest(dump, salt)

        return salt + digest + dump

    def unpack(self, packed):
        salt = packed[:self.salt_len]
        digest = packed[self.salt_len:self.salt_len + self.hash_len]
        dump = packed[self.salt_len + self.hash_len:]

        if digest != self.digest(dump, salt):
            raise BadDataError, 'Corrupt or tampered datastring'

        return self.load(dump)



if __name__ == '__main__':
    formdata = {
        'email':  'john@example.org',
        'password':  'example',
    }

    s = SignedURLSafeSerializer('Put your secret here.')
    packed = s.pack(formdata)

    print packed
    print s.unpack(packed)

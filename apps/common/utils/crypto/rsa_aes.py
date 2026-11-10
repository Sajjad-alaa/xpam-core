import base64
import hashlib
from django.conf import settings

from Cryptodome import Random
from Cryptodome.Cipher import AES, PKCS1_v1_5
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .base import BaseCryptoSuite

from .common import padding_key


def gen_key_pair(length=2048):
    """ 生成加密key
    用于登录页面提交用户名/密码时，对密码进行加密（前端）/解密（后端）
    """
    random_generator = Random.new().read
    rsa = RSA.generate(length, random_generator)
    rsa_private_key = rsa.exportKey().decode()
    rsa_public_key = rsa.publickey().exportKey().decode()
    return rsa_private_key, rsa_public_key


class AESCrypto:
    """
    AES
    除了MODE_SIV模式key长度为: 32, 48, or 64,
    其余key长度为16, 24 or 32
    详细见AES内部文档
    CBC模式传入iv参数
    本例使用常用的ECB模式
    """

    def __init__(self, key):
        self.key = padding_key(key, 32)
        self.aes = AES.new(self.key, AES.MODE_ECB)

    @staticmethod
    def to_16(key):
        """
        转为16倍数的bytes数据
        :param key:
        :return:
        """
        key = bytes(key, encoding="utf8")
        while len(key) % 16 != 0:
            key += b'\0'
        return key  # 返回bytes

    def aes(self):
        return AES.new(self.key, AES.MODE_ECB)

    def encrypt(self, text):
        cipher = base64.encodebytes(self.aes.encrypt(self.to_16(text)))
        return str(cipher, encoding='utf8').replace('\n', '')  # 加密

    def decrypt(self, text):
        text_decoded = base64.decodebytes(bytes(text, encoding='utf8'))
        return str(self.aes.decrypt(text_decoded).rstrip(b'\0').decode("utf8"))


class AESCryptoGCM:
    """
    使用AES GCM模式

    XPAM: OpenSSL's AES-GCM (cryptography) instead of PyCryptodome's: the same algorithm and the same stored
    format — header (additional data), 16-byte nonce and 16-byte tag, base64, before the ciphertext — so every
    value either library wrote opens with the other. PyCryptodome built a new GCM cipher (its GHASH tables) for
    each value, about 0.2 ms; OpenSSL does it in microseconds, which matters where lists decrypt every row.
    """

    def __init__(self, key):
        self.key = self.process_key(key)
        self._aead = AESGCM(self.key)

    @staticmethod
    def process_key(key):
        if not isinstance(key, bytes):
            key = bytes(key, encoding='utf-8')

        if len(key) >= 32:
            return key[:32]

        return pad(key, 32)

    def encrypt(self, text):
        """
        加密text，并将 header, nonce, tag (3*16 bytes, base64后变为 3*24 bytes)
        附在密文前。解密时要用到。
        """
        header = get_random_bytes(16)
        nonce = get_random_bytes(16)
        sealed = self._aead.encrypt(nonce, bytes(text, encoding='utf-8'), header)
        ciphertext, tag = sealed[:-16], sealed[-16:]
        return ''.join(base64.b64encode(part).decode('utf-8') for part in (header, nonce, tag, ciphertext))

    def decrypt(self, text):
        """
        提取header, nonce, tag并解密text。
        """
        metadata = text[:72]
        header = base64.b64decode(metadata[:24])
        nonce = base64.b64decode(metadata[24:48])
        tag = base64.b64decode(metadata[48:])
        ciphertext = base64.b64decode(text[72:])
        try:
            plain_text_bytes = self._aead.decrypt(nonce, ciphertext + tag, header)
        except InvalidTag:
            raise ValueError('MAC check failed') from None  # (PyCryptodome's error for a wrong key or a changed value)
        return plain_text_bytes.decode('utf-8')


def get_aes_crypto(key=None, mode='GCM'):
    if key is None:
        key = settings.SECRET_KEY
    if mode == 'GCM':
        return AESCryptoGCM(key)
    else:
        return AESCrypto(key)


class Hasher:
    name = 'sha256'
    block_size = 64
    digest_size = 32

    def __init__(self, data):
        self.__data = data

    def hexdigest(self):
        return hashlib.sha256(self.__data).hexdigest()

    def digest(self):
        return bytes.fromhex(self.hexdigest())

    @staticmethod
    def hash(cls, msg=b''):
        return cls(msg)

    def update(self, data):
        self.__data += data

    @classmethod
    def copy(cls, data):
        return cls(data)


class RsaAesCryptoSuite(BaseCryptoSuite):
    crypto = None
    _key = None

    def __init__(self, key, mode='ECB'):
        self.mode = mode
        if key:
            self.key = key

    @property
    def key(self):
        return self._key

    @key.setter
    def key(self, value):
        self._key = value
        self.crypto = get_aes_crypto(value, self.mode)
    
    def encrypt(self, text):
        return self.crypto.encrypt(text)
    
    def decrypt(self, cipher_text):
        return self.crypto.decrypt(cipher_text)

    def gen_key_pair(self, length=2048):
        return gen_key_pair(length)

    def encrypt_with_key_pair(self, message, rsa_public_key):
        """ 加密登录密码 """
        key = RSA.importKey(rsa_public_key)
        cipher = PKCS1_v1_5.new(key)
        cipher_text = base64.b64encode(cipher.encrypt(message.encode())).decode()
        return cipher_text
    
    def decrypt_with_key_pair(self, cipher_text, rsa_private_key):
        """ 解密登录密码 """
        if rsa_private_key is None:
            # rsa_private_key 为 None，可以能是API请求认证，不需要解密
            return cipher_text

        key = RSA.importKey(rsa_private_key)
        cipher = PKCS1_v1_5.new(key)
        cipher_decoded = base64.b64decode(cipher_text.encode())
        # Todo: 弄明白为何要以下这么写，https://xbuba.com/questions/57035263
        if len(cipher_decoded) == 127:
            hex_fixed = '00' + cipher_decoded.hex()
            cipher_decoded = base64.b16decode(hex_fixed.upper())
        message = cipher.decrypt(cipher_decoded, b'error').decode()
        return message
    
    def hash(self, msg):
        return Hasher.hash(Hasher, msg)


aes_ecb_crypto = get_aes_crypto(mode='ECB')
aes_crypto = get_aes_crypto(mode='GCM')
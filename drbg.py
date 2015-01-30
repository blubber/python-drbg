
import hashlib
import hmac
import math
import re
import os
import sys

from functools import reduce

try:
    import Crypto.Cipher.AES
    from Crypto.Util.strxor import strxor
except ImportError:
    WITH_CRYPTO = False

PY3 = sys.version_info.major == 3

# List of supported hash algorithms.
DIGESTS = ['sha1', 'sha224', 'sha256', 'sha384', 'sha512']

# Maximum length for entropy input, nonces, personaliation strings
# and additional input. (in bytes).
MAX_ENTROPY_LENGTH = 2**21

# Number of generate calls before a reseed is required.
RESEED_INTERVAL = 2**24

class Error (Exception): pass
class UnknownAlgorithm (Exception): pass
class ReseedRequired (Exception): pass


def bytes2long (b):
    if PY3:
        num = int.from_bytes(b, 'big')
    else:
        length = len(b) - 1
        num = sum(c * 256**(length - exp) for exp, c in enumerate(b))
        
    return num


def long2bytes (l):
    b = bytearray()

    while l > 0:
        b.append(l & 0xff)
        l >>= 8

    b.reverse()
    return bytes(b)


class DRBG (object):
    ''' Deterministic Random Bit Generator base class.

    :param entropy: A string of random bytes, minimum length is
                    algorithm specific.
    :type entropy: :class:`bytes` or :class:`bytearray`.
    :param data: Optional personalization string.
    :type data: :class:`bytes` or :class:`bytearray`.

    .. warning:: Supplying the DRBG with poor quality values for `entropy`
                 or `nonce` will result in low quality output. A good
                 cross-platform source of randomness is `os.urandom()`.
    '''

    def __init__ (self, entropy, data=None):
        if not isinstance(entropy, (bytes, bytearray)):
            raise TypeError(('Expected bytes or bytearray for entropy'
                             'got {}').format(type(entropy.__name__)))

        if not data is None and not not isinstance(data, (bytes, bytearray)):
            raise TypeError(('Expected bytes or bytearray for data'
                             'got {}').format(type(data.__name__)))

        self.reseed_counter = 1

    def generate (self, count, data=None):
        ''' Generate the next `count` random bytes.

        :param count: The number of bytes to return.
        :param data: Optional addition data.
        :type data: :class:`bytes` or :class:`bytearray`.

        :returns: :class:`bytes`.

        :raises: A :class:`ValueError` is raised if `count` is out of range,
                 maximum allowed number is algorithm dependent and specified
                 in SP 800-90A. A :class:`ReseedRequired` is raised if
                 the generator should be reseeded.
        '''
        if not 0 < count < self.max_request_size:
            raise ValueError('Count out of range.')

        if not data is None and not isinstance(data, (bytes, bytearray)):
            raise TypeError('Expected bytes or bytearray for data.')

        if not data is None and len(data) > MAX_ENTROPY_LENGTH:
            raise ValueError('Too much data.')

        if self.reseed_counter > RESEED_INTERVAL:
            raise ReseedRequired()

        out = self._generate(count, data)
        self.reseed_counter += 1
        return out


    def reseed (self, entropy, data=None):
        ''' Reseed the DRBG.

        :param entropy: A string of random bytes, minimum length is
                        algorithm specific.
        :type entropy: :class:`bytes` or :class:`bytearray`.
        :param data: Optional personalization string.
        :type data: :class:`bytes` or :class:`bytearray`.
        '''
        if not isinstance(entropy, (bytes, bytearray)):
            raise TypeError(('Expected bytes or bytearray for entropy'
                             'got {}').format(type(entropy.__name__)))

        if not data is None and not not isinstance(data, (bytes, bytearray)):
            raise TypeError(('Expected bytes or bytearray for data'
                             'got {}').format(type(data.__name__)))

        self._reseed(entropy, data)

    def _generate (self, count, data):
        ''' Implementations should override this to return random bytes. '''
        raise NotImplementedError()

    def _reseed (self, entropy, data=None):
        ''' Implementations should override this to reseed. '''



class CTRDRBG (DRBG):
    ''' DRBG based on a block cipher in counter mode.

    :param name: A string that describes the cipher and key length to use.
    :type cipher: :class:`str`.
    :param entropy: Refer to :class:`DRBG`.
    :param nonce: Refer to :class:`DRBG`.

    The following ciphers are used:

    name  description          alt. name
    ======  =================  ============
    tdea    3 key triple des   des, 3des
    aes128  AES 128 bit        aes, aes-128
    aes196  AES 196 bit        aes-196
    aes256  AES 256 bit        aes-256
    ======  =================  ============

    Contrary to SP 800-90A all ciphers only support their highest security
    strength setting.
    '''

    def __init__ (self, name, entropy, data=None):
        super(CTRDRBG, self).__init__(entropy, data)

        ciphers = {
            'aes'    : (Crypto.Cipher.AES, 128),
            'aes128' : (Crypto.Cipher.AES, 128),
            'aes-128': (Crypto.Cipher.AES, 128),
            'aes192' : (Crypto.Cipher.AES, 192),
            'aes-192': (Crypto.Cipher.AES, 192),
            'aes256' : (Crypto.Cipher.AES, 256),
            'aes-256': (Crypto.Cipher.AES, 256),
        }

        if not name.lower() in ciphers:
            raise ValueError('Unknown cipher: {}'.format(name))

        self.cipher, self.keylen = ciphers[name.lower()]
        self.is_aes = name.lower().startswith('aes')

        if self.is_aes:
            self.max_request_size = 2**13   # bytes or 2**16 bits
            self.outlen = 128

        self.seedlen = (self.outlen + self.keylen) // 8

        if len(entropy) != self.seedlen:
            raise ValueError('Entropy should be exachtly {} bytes long'.format(
                             self.seedlen))

        if data:
            if len(data) > self.seedlen:
                raise ValueError('Only {} bytes of data supported.'.format(
                                 self.seedlen))

            delta = len(entropy) - len(data)

            if delta > 0:
                data = (b'\x00' * delta) + data

            seed_material = strxor(entropy, data)
        else:
            seed_material = entropy

        Key = b'\x00' * (self.keylen // 8)
        V = b'\x00' * (self.outlen // 8)
        self.__key, self.__V = self.__update(seed_material, Key, V)

    def _generate (self, count, data=None):
        if data and len(data) > self.seedlen:
            raise ValueError('Too much data.')

        if data:
            data += b'\x00' * (self.seedlen - len(data))
            self.__key, self.__V = self.__update(data, self.__key,
                                                 self.__V)

        temp = b''
        K, V = self.__key, self.__V

        while len(temp) < count:
            V = long2bytes((bytes2long(V) + 1) % 2**self.outlen)

            if len(V) < self.outlen // 8:
                V = (b'\x00' * (self.outlen // 8 - len(V))) + V

            temp += self.cipher.new(K).encrypt(V)

        self.__key, self.__V = self.__update(data or b'', K, V)
        return temp[:count]

    def _reseed (self, entropy, data=None):
        if data and len(data) > self.seedlen:
            raise ValueError('Too much data.')

        if len(entropy) != self.seedlen:
            raise ValueError('Too much entropy.')

        if data:
            data = (b'\x00' * (self.seedlen - len(data))) + data
            seed_material = strxor(entropy, data)
        else:
            seed_material = entropy

        self.__key, self.__V = self.__update(seed_material, self.__key,
                                             self.__V)
        self.reseed_counter = 1

    def __update (self, provided_data, Key, V):
        temp = b''

        while len(temp) < self.seedlen:
            V = long2bytes((bytes2long(V) + 1) % 2**self.outlen)

            if len(V) < self.outlen // 8:
                V = b'\x00' * (16 - len(V)) + V

            output_block = self.cipher.new(Key).encrypt(V)
            temp += output_block
        
        temp = temp[:self.seedlen]

        if len(provided_data) < self.seedlen:
            provided_data = b'\x00' * (self.seedlen - len(provided_data)) + provided_data

        temp = strxor(temp, provided_data)
        Key = temp[:self.keylen // 8]
        V = temp[-self.outlen // 8:]

        return Key, V


    # def _create_df (self):
    #     cipher_const = getattrrr(Crypto.Cipher. self.cipher).new

    #     def BCC (key, data):
    #         assert len(data) % (self.outlen // 8) == 0

    #         bytelen = self.outlen // 8
    #         chaining_value = b'\00' * bytelen
    #         cipher = cipher_const(key)

    #         for i in range(0, len(data) // bytelen, bytelen)
    #             input_block = strxorchaining_value, data[i:i+bytelen]
    #             chaining_value = cipher.encrypt(input_block)

    #         return chaining_value


    #     def df (input_string, no_of_bits_to_return):
    #         L = len(input_string)
    #         N = no_of_bits_to_return // 8
    #         bytelen = self.outlen // 8

    #         S = bytearray((L >> shift) & 0xff for shift in range(3, -1, -1)) +\
    #             bytearray((N >> shift) & 0xff for shift in range(3, -1, -1)) +\
    #             input_string + b'\x80'

    #         if len(S) % bytelen > 0:
    #             S += b'\x00' * (bytelen - len(S) % bytelen)

    #         temp = b'\x00'
    #         i = 0
    #         K = bytearray(range(0, 32))[:bytelen]

    #         while len(temp) < (self.keylen + self.outlen) // 8:
    #             IV = bytearray((i >> shift) & 0xff for shift in range(3, -1, -1)) + \
    #                 (b'\x00' * (bytelen - 4))
    #             temp = temp + BCC(K, (IV + S))
    #             i += 1

    #         K = temp[:self.keylen // 8]
    #         X = temp[self.keylen // 8:(self.keylen + self.outlen) // 8]
    #         temp = b'\x00'

    #         while len(temp) < len(no_of_bits_to_return) // 8:
    #             cipher = Crypto.Cipher.AES.new(K)
    #             X = cipher.encrypt(X)
    #             temp += X

    #         return temp[:no_of_bits_to_return // 8]

    #     return df



class DigestDRBG (object):

    max_entropy_length = 2**32
    max_personalization_string_length = 2**32
    max_additional_input_length = 2**32
    max_number_of_bits_per_request = 2**19
    reseed_interval = 2**32

    def __init__ (self, digest, entropy_input, nonce, personalization_string=None):
        if not digest in DIGESTS:
            raise ValueError('Unsupported digest {}'.format(digst))

        self.digest = digest

        if not isinstance(entropy_input, (bytes, bytearray)):
            raise TypeError('entropy_input: expected bytes or bytearray.')

        if not isinstance(nonce, (bytes, bytearray)):
            raise TypeError('nonce: expected bytes or bytearray.')

        if not personalization_string is None and \
                not isinstance(personalization_string, (bytes, bytearray)):
            raise TypeError('personalization_string: expected bytes or bytearray.')

        if not self.security_strength <= 8 * len(entropy_input) <= self.max_entropy_length:
            raise Error('Entropy length invalid.')

        if personalization_string and 8 * len(personalization_string) > self.max_personalization_string_length:
            raise Error('Personalization string too long')

        self.reseed_counter = 1

    @property
    def security_strength (self):
        return self.outlen // 2

    @property
    def outlen (self):
        h = getattr(hashlib, self.digest)
        return 8 * h().digest_size


class HashDRBG (DigestDRBG):

    def __init__ (self, digest, entropy_input, nonce, personalization_string=None):
        super(HashDRBG, self).__init__(digest, entropy_input, nonce, personalization_string)
        self.seedlen = 440

        self.df = self._create_hash_df(getattr(hashlib, digest))

        personalization_string = personalization_string or b''

        self.__V = self.df(entropy_input + nonce, self.seedlen)
        self.__C = self.df(b'\x00' + self.__V, self.seedlen)


    def reseed (self, entropy_input, additional_input=None):
        additional_input = additional_input or b''
        self.__V = self.df(b'\x01' + self.__V + entropy_input + additional_input, self.seedlen)
        self.__C = self.df(b'\x00' + self.__V, self.seedlen)
        self.reseed_counter = 1


    def generate (self, requested_length, additional_input=None):
        digest = getattr(hashlib, self.digest)

        def hashgen (req, V):
            m = math.ceil(req / self.outlen)
            data = V
            w = b''
            for i in range(m):
                w += digest(data).digest()
                data = long2bytes((bytes2long(data) + 1) % 2**self.seedlen)
            return w[:(req + 4) // 8]


        if not additional_input is None:
            w = digest(b'\x02' + self.__V + additional_input).digest()
            V = long2bytes((bytes2long(self.__V) + bytes2long(w)) % 2**self.seedlen)
        else:
            V = self.__V

        out = hashgen(requested_length, V)
        H = digest(b'\x03' + V).digest()
        V = long2bytes((bytes2long(V) + bytes2long(H) + bytes2long(self.__C) + self.reseed_counter) % 2**self.seedlen)
        self.__V = V
        return out        

    def _create_hash_df (self, primitive):

        def df (input_string, no_of_bits_to_return):
            output = b''
            iterations = math.ceil(no_of_bits_to_return / self.outlen)
            return_bit_count = bytearray([
                no_of_bits_to_return >> 24,
                (no_of_bits_to_return >> 16) & 0xff,
                (no_of_bits_to_return >> 8) & 0xff,
                no_of_bits_to_return & 0xff
            ])

            for counter in range(iterations):
                output += primitive(chr((counter + 1) % 255).encode('utf-8') +
                                    return_bit_count + input_string).digest()

            return output[:(no_of_bits_to_return + 4) // 8]

        return df



class HMACDRBG (DigestDRBG):

    def __init__ (self, digest, entropy_input, nonce, personalization_string=None):        
        super(HMACDRBG, self).__init__(digest, entropy_input, nonce, personalization_string)

        outlen = self.outlen // 8
        self.__key, self.__V = self.update(b'\0' * outlen, b'\x01' * outlen,
                                           entropy_input, nonce,
                                           personalization_string)


    def generate (self, requested_length, additional_input=None):
        requested_length = (requested_length + 4) // 8

        K, V = self.update(self.__key, self.__V, additional_input)
        out = b''

        while len(out) < requested_length:
            V = self._mac(K, V)
            out += V

        self.reseed_counter += 1
        return out[:requested_length]


    def update (self, K, V, *provided_input):
        K = self._mac(K, V, b'\x00', *provided_input)
        V = self._mac(K, V)

        if provided_input:
            K = self._mac(K, V, b'\x01', *provided_input)
            V = self._mac(K, V)

        return K, V


    def reseed (self, entropy_input, additional_input=None):
        self.__key, self.__V = self.update(self.__key, self.__V, entropy_input, additional_input)
        self.reseed_counter = 1


    def _mac (self, K, V, *Vs):
        value = V + b''.join(v for v in Vs if v is not None)
        mac = hmac.new(K, value, digestmod=self.digest)
        return mac.digest()


def new (name, personalization_string=None):
    entropy = os.urandom(128)
    nonce = os.urandom(128)
    drbg = None

    matches = re.match('(sha[0-9]{1,3})(hmac)?', name.lower())

    if matches:
        digest = matches.group(1)
        use_hmac = not matches.group(2) is None

        if digest not in DIGESTS:
            raise ValueError('Unsupported digest {}'.format(digest))

        if use_hmac:
            drbg = HMACDRBG(digest, entropy, nonce, personalization_string)

    return drbg




'''
This module implements methods for (2,3) threshold secret sharing for splitting
secrets into three shares. None of the shares alone give away any information
about the secret (other than the length) but any combination of two shares is
able to fully recover the secret.
'''

from os import urandom as __urandom

def split_bytes(m):
    '''
    Splits m into 3 shares using (2,3) threshold secret sharing algorithm
    defined by:
        m = secret byte with bits [m7 m6 m5 m4 m3 m2 m1 m0]
        r = random byte
        s0 = [ 0  0  0  0 m7 m6 m5 m4] ^ r
        s1 = [m3 m2 m1 m0  0  0  0  0] ^ r
        s2 = [m7 m6 m5 m4 m3 m2 m1 m0] ^ r
    The first byte of each share is a tag denoting which share it is.
    '''
    if isinstance(m, str):
        m = bytearray(m, 'utf8')
    n = len(m)
    r = bytearray(__urandom(n))
    s0 = bytearray(n + 1)
    s0[0] = 0x00
    s1 = bytearray(n + 1)
    s1[0] = 0x01
    s2 = bytearray(n + 1)
    s2[0] = 0x02
    for i in range(n):
        x = m[i]
        y = r[i]
        j = i + 1
        s0[j] = ((x & 0xf0) >> 4) ^ y
        s1[j] = ((x & 0x0f) << 4) ^ y
        s2[j] = x ^ y
    return [s0, s1, s2]

def join_bytes(a, b):
    '''
    Recovers secret from any two tagged shares.
    '''
    if len(a) != len(b):
        raise ValueError('size mismatch')
    if len(a) < 1:
        raise ValueError('invalid shares')
    if a[0] > b[0]:
        a, b = b, a
    m = bytearray(len(a) - 1)
    if a[0] == 0x00 and b[0] == 0x01:
        __join_bytes_01(m, a, b)
    elif a[0] == 0x00 and b[0] == 0x02:
        __join_bytes_02(m, a, b)
    elif a[0] == 0x01 and b[0] == 0x02:
        __join_bytes_12(m, a, b)
    else:
        raise ValueError('invalid shares')
    return m

def __join_bytes_01(m, a, b):
    '''
    when a = s0 and b = s1
        c = a ^ b
        m = [c3 c2 c1 c0 0 0 0 0] | [0 0 0 0 c7 c6 c5 c4]
    '''
    for i in range(len(m)):
        c = a[i + 1] ^ b[i + 1]
        m[i] = ((c << 4) & 0xf0) | ((c >> 4) & 0x0f)

def __join_bytes_02(m, a, b):
    '''
    when a = s0 and b = s2
        c = a ^ b
        m = [0 0 0 0 c7 c6 c5 c4] ^ c
    '''
    for i in range(len(m)):
        c = a[i + 1] ^ b[i + 1]
        m[i] = ((c & 0xf0) >> 4) ^ c

def __join_bytes_12(m, a, b):
    '''
    when a = s1 and b = s2
        c = a ^ b
        m = [c3 c2 c1 c0 0 0 0 0] ^ c
    '''
    for i in range(len(m)):
        c = a[i + 1] ^ b[i + 1]
        m[i] = ((c & 0x0f) << 4) ^ c

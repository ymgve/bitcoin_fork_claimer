import socket, struct, os, hashlib, cStringIO, time, sys, random

from aes import *

chainid = "0106bc59af196e3a96cec0120bcc313589338fd1e84f81c07cb5cdd1806655c0".decode("hex")

N = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fL
R = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141L
A = 0L
B = 7L
gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798L
gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8L

b58ab = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58csum(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()[0:4]
    
def b58decode(s, checksum=True):
    idx = 0
    while s[idx] == "1":
        idx += 1
        
    n = 0
    for c in s[idx:]:
        n = n * 58 + b58ab.index(c)
        
    res = long2byte(n)
    res = idx * "\x00" + res
    
    if checksum:
        res, cs = res[:-4], res[-4:]
        assert cs == b58csum(res), "base58 checksum failed"
        
    return res

def b58encode(s, checksum=True):
    if checksum:
        s += b58csum(s)
        
    idx = 0
    while s[idx] == "\x00":
        idx += 1
        
    n = byte2long(s)
    res = ""
    while n > 0:
        res = b58ab[n % 58] + res
        n /= 58
        
    return "1" * idx + res
    
def byte2long(s):
    res = 0
    for c in s:
        res = (res << 8) | ord(c)
    return res
    
def long2byte(n, sz=None):
    res = ""
    while n > 0:
        res = chr(n & 0xff) + res
        n >>= 8
        
    if sz is not None:
        res = res.rjust(sz, "\x00")
        
    return res
        
def modinv(x, n):
    return pow(x, n-2, n)

class Point(object):
    def __init__(self, x, y, inf=False):
        self.x = x
        self.y = y
        self.inf = inf
        
def curve_add(p, q, N):
    if p.inf:
        return q
        
    if q.inf:
        return p
    
    if p.x == q.x:
        if p.y == q.y:
            d1 = (3 * p.x * p.x) % N
            d2 = (2 * p.y) % N
        else:
            return Point(-1, -1, True)
    else:
        d1 = (q.y - p.y) % N
        d2 = (q.x - p.x) % N

    d2i = modinv(d2, N)
    d = (d1 * d2i) % N
        
    resx = (d * d - p.x - q.x) % N
    resy = (d * (p.x - resx) - p.y) % N
    
    return Point(resx, resy)
    
def scalar_mul(scalar, p, N):
    t = p
    res = None
    while scalar != 0:
        if scalar & 1 == 1:
            if res is None:
                res = t
            else:
                res = curve_add(res, t, N)
        
        t = curve_add(t, t, N)
        
        scalar = scalar >> 1
        
    return res

def sign(privkey, z):
    while True:
        k = byte2long(os.urandom(256 / 8))
        if k >= 1 and k < R:
            break
    
    p = scalar_mul(k, Point(gx, gy), N)
    r = p.x % R
    assert r != 0
    
    ki = modinv(k, R)
    s = (ki * (z + r * privkey)) % R
    assert s != 0
    v = p.y & 1
    if s > (R / 2):
        s = R - s
        v ^= 1
    
    return v + 27 + 4, r, s
    
def serialize_signature(signature):
    v, r, s = signature
    return chr(v) + long2byte(r, 32) + long2byte(s, 32)
    
k0 = 0xc3a5c85c97cb3127
k1 = 0xb492b66fbe98f273
k2 = 0x9ae16a3b2f90404f
lo64mask = ((1 << 64) - 1)

def Fetch64(s):
    t = struct.unpack("<Q", s)[0]
    return t
    
def Fetch32(s):
    return struct.unpack("<I", s)[0]
    
def ShiftMix(val):
    val &= lo64mask
    return val ^ (val >> 47)
    
def Rotate(val, n):
    val &= lo64mask
    return ((val >> n) | (val << (64-n))) & lo64mask

def BADHashLen16(v, u, mul=0x9ddfea08eb382d69):
    u &= lo64mask
    v &= lo64mask
    mul &= lo64mask
    a = ((u ^ v) * mul) & lo64mask
    a ^= (a >> 47)
    b = ((v ^ a) * mul) & lo64mask
    b ^= (b >> 47)
    b = (b * mul) & lo64mask
    return b

def HashLen0to16(s):
    if len(s) >= 8:
        mul = (k2 + len(s) * 2) & lo64mask
        a = (Fetch64(s[:8]) + k2) & lo64mask
        b = Fetch64(s[-8:]) & lo64mask
        c = (Rotate(b, 37) * mul + a) & lo64mask
        d = ((Rotate(a, 25) + b) * mul) & lo64mask
        return HashLen16(c, d, mul)
        
    if len(s) >= 4:
        mul = (k2 + len(s) * 2) & lo64mask
        a = Fetch32(s[:4])
        return HashLen16(len(s) + (a << 3), Fetch32(s[-4:]), mul)
        
    if len(s) > 0:
        a = ord(s[0])
        b = ord(s[len(s) >> 1])
        c = ord(s[-1])
        y = a + (b << 8)
        z = len(s) + (c << 2)
        return (ShiftMix(y * k2 ^ z * k0) * k2) & lo64mask
        
    return k2

def BADCityMurmur(s, seed):
    a = seed & lo64mask
    b = seed >> 64
    c = 0
    d = 0
    
    l = len(s) - 16
    if l <= 0:
        a = (ShiftMix(a * k1) * k1) & lo64mask
        c = (b * k1 + HashLen0to16(s)) & lo64mask
        if len(s) >= 8:
            d = (a + Fetch64(s[:8])) & lo64mask
        else:
            d = (a + c) & lo64mask
        d = ShiftMix(d)
    else:
        c = BADHashLen16(Fetch64(s[-8:]) + k1, a)
        d = BADHashLen16(b + len(s), c + Fetch64(s[-16:-8]))
        a = (a + d) & lo64mask
        
        while True:
            a ^= (ShiftMix(Fetch64(s[:8]) * k1) * k1) & lo64mask
            a = (a * k1) & lo64mask
            b ^= a
            c ^= (ShiftMix(Fetch64(s[8:16]) * k1) * k1) & lo64mask
            c = (c * k1) & lo64mask
            d ^= c
            s = s[16:]
            l -= 16
            if l <= 0:
                break

    a = BADHashLen16(a, c)
    b = BADHashLen16(d, b)
    return (a ^ b) << 64 | BADHashLen16(b, a)
    
def BADCityHash128WithSeed(s, seed):
    if len(s) < 128:
        return BADCityMurmur(s, seed)
    else:
        raise Exception("Not implemented")

def BADCityHash128(s):
    if len(s) >= 16:
        res = BADCityHash128WithSeed(s[16:], Fetch64(s[:8]) << 64 | ((Fetch64(s[8:16]) + k0) & lo64mask))
    else:
        res = BADCityHash128WithSeed(s, k0 << 64 | k1)
        
    return res

def readvarint(sio):
    n = 0
    p = 0
    while True:
        c = ord(sio.read(1))
        n |= (c & 0x7f) << p
        if c & 0x80 == 0:
            break
            
        p += 7
        
    return n
    
def makevarint(n):
    s = ""
    while n >= 0x80:
        s += chr(0x80 | (n & 0x7f))
        n >>= 7
    s += chr(n)
    return s
    
def readstring(sio):
    size = ord(sio.read(1))
    return sio.read(size)
    
def read_variant_object(sio):
    res = {}
    numentries = ord(sio.read(1))
    for i in xrange(numentries):
        key = readstring(sio)
        valuetype = ord(sio.read(1))
        if valuetype == 5:
            value = readstring(sio)
        elif valuetype == 2:
            value = struct.unpack("<Q", sio.read(8))[0]
        else:
            print valuetype
            raise Exception("invalid valuetype")
            
        res[key] = value
        print key, valuetype, value
        
def lengthprefixed(s):
    return chr(len(s)) + s
    
def wif2privkey(s):
    s = b58decode(s)
    keytype = ord(s[0])
    
    if len(s) == 34 and s[-1] == "\x01":
        compressed = 1
    elif len(s) == 33:
        compressed = 0
    else:
        raise Exception("Unknown private key WIF format!")
        
    return keytype, byte2long(s[1:33]), compressed

def serializepubkey(p, compressed):
    if compressed:
        if p.y & 1 == 1:
            return "\x03" + long2byte(p.x, 32)
        else:
            return "\x02" + long2byte(p.x, 32)
    else:
        return "\x04" + long2byte(p.x, 32) + long2byte(p.y, 32)

def unserializepubkey(s):
    x = byte2long(s[1:33])
    
    if s.startswith("\x04"):
        y = byte2long(s[33:65])
        compressed = 0
    else:
        beta = pow(x**3 + A*x + B, (N+1)/4, N)
        if (beta + ord(s[0])) & 1 == 1:
            y = N - beta
        else:
            y = beta
        compressed = 1
    
    assert (x**3 + A*x + B) % N == (y**2) % N
    
    return Point(x, y), compressed

def pubkey2h160(p, compressed):
    s = serializepubkey(p, compressed)
    s = hashlib.sha256(s).digest()
    h = hashlib.new("ripemd160")
    h.update(s)
    return h.digest()
    
def pubkey2addr(p, compressed):
    s = pubkey2h160(p, compressed)
    return b58encode("\x00" + s)

def recover_pubkey(v, r, s, z):
    beta = pow(r**3 + A*r + B, (N+1)/4, N)
    if beta & 1 == (v - 31) & 1:
        R1 = Point(r, beta)
    else:
        R1 = Point(r, N - beta)

    rinv = modinv(r, R)
    t1 = scalar_mul(s, R1, N)
    t2 = scalar_mul(z, Point(gx, gy), N)
    t2 = Point(t2.x, N - t2.y)
    t = curve_add(t1, t2, N)
    res = scalar_mul(rinv, t, N)
    return res
    
def generate_balance_addr(addr):
    s = "\x00" + "\x00" * 8 + "\x01" + lengthprefixed(b58decode(addr, False) + "\x00")
    s = hashlib.sha256(s).digest()
    h = hashlib.new("ripemd160")
    h.update(s)
    balance_addr = b58decode(b58encode("\x00" + h.digest()), False)
    return balance_addr
    
def generate_tx(wifkey, srcaddr, destaddr, satoshis, fee):
    keytype, privkey, compressed = wif2privkey(wifkey)
    pubkey = scalar_mul(privkey, Point(gx, gy), N)
    addr = pubkey2addr(pubkey, compressed)

    assert addr == srcaddr
    assert b58encode(b58decode(destaddr)) == destaddr

    expiry = struct.pack("<I", int(time.time()) + 86400)
    to_sign = expiry + "\x00" + "\x02"
    to_sign += "\x01" + lengthprefixed(generate_balance_addr(srcaddr) + struct.pack("<Q", satoshis) + "\x00")
    to_sign += "\x02" + lengthprefixed(struct.pack("<Q", satoshis - fee) + "\x00" + "\x00" * 8 + "\x01" + lengthprefixed(b58decode(destaddr, False) + "\x00"))

    z = byte2long(hashlib.sha256(to_sign + chainid).digest())
    signature = sign(privkey, z)
    signed_tx = to_sign + "\x01" + serialize_signature(signature)
    
    print "raw transaction"
    print signed_tx.encode("hex")
    print

    return signed_tx

def get_consent(consentstring):
    print "\nWrite '%s' to continue" % consentstring

    answer = raw_input()
    if answer != consentstring:
        raise Exception("User did not write '%s', aborting" % consentstring)

class STCP(object):
    def __init__(self):
        self.myprivkey = byte2long(os.urandom(32))
        self.mypubkey = scalar_mul(self.myprivkey, Point(gx, gy), N)

    def recv_all(self, n):
        data = ""
        while len(data) < n:
            block = self.sc.recv(n - len(data))
            if len(block) == 0:
                print repr(data)
                raise Exception("Server disconnected")
            data += block

        return data
        
    def connect(self, address):
        print "trying to connect to", address
        self.sc = socket.create_connection(address)
        self.sc.send(serializepubkey(self.mypubkey, 1))

        peerpub = self.recv_all(33)
        self.peerpub, compressed = unserializepubkey(peerpub)
        self.pubkey = scalar_mul(self.myprivkey, self.peerpub, N)
        self.sharedsecret = hashlib.sha512(serializepubkey(self.pubkey, 1)[1:]).digest()
        t = BADCityHash128(self.sharedsecret)
        IV = struct.pack("<QQ", t >> 64, t & lo64mask)
            
        self.rxcrypt = AESModeOfOperationCBC(hashlib.sha256(self.sharedsecret).digest(), iv = IV)
        self.txcrypt = AESModeOfOperationCBC(hashlib.sha256(self.sharedsecret).digest(), iv = IV)

    def recv_message(self):
        data = self.rxcrypt.decrypt(self.recv_all(16))
        datasize, msgtype = struct.unpack("<II", data[0:8])
        to_read = (8 + datasize - 1) & 0xfffffff0
        ct = self.recv_all(to_read)
        for i in xrange(0, len(ct), 16):
            data += self.rxcrypt.decrypt(ct[i:i+16])
        return msgtype, data[8:8+datasize]
        
    def send_message(self, msgtype, msg):
        to_send = struct.pack("<II", len(msg), msgtype) + msg
        padlen = 16 - (len(to_send) % 16)
        if padlen == 16:
            padlen = 0
            
        to_send += "\x00" * padlen
        data = ""
        for i in xrange(0, len(to_send), 16):
            data += self.txcrypt.encrypt(to_send[i:i+16])
        
        self.sc.sendall(data)
        
    def send_hello(self):
        serpubkey = serializepubkey(self.mypubkey, 1)
        signature = sign(self.myprivkey, byte2long(hashlib.sha256(self.sharedsecret).digest()))
        sersignature = serialize_signature(signature)
        
        msg = ""
        msg += lengthprefixed("fbtcshares_client")
        msg += struct.pack("<I", 106)
        msg += struct.pack("<BBBB", 10, 0, 0, 2)[::-1]
        msg += struct.pack("<HH", 40032, 40032)
        msg += serpubkey
        msg += sersignature
        msg += chainid
        msg += "\x0b"
        msg += lengthprefixed("fbtcshares_git_revision_sha") + "\x05" + lengthprefixed("699c9438346aab9217f9c579fcd9e96149a981fa")
        msg += lengthprefixed("fbtcshares_git_revision_unix_timestamp") + "\x02" + struct.pack("<Q", 1514379733)
        msg += lengthprefixed("fc_git_revision_sha") + "\x05" + lengthprefixed("699c9438346aab9217f9c579fcd9e96149a981fa")
        msg += lengthprefixed("fc_git_revision_unix_timestamp") + "\x02" + struct.pack("<Q", 1514379733)
        msg += lengthprefixed("platform") + "\x05" + lengthprefixed("linux")
        msg += lengthprefixed("bitness") + "\x02" + struct.pack("<Q", 64)
        msg += lengthprefixed("node_id") + "\x05" + lengthprefixed(os.urandom(32).encode("hex"))
        msg += lengthprefixed("last_known_block_hash") + "\x05" + lengthprefixed("0000000000000000000000000000000000000000")
        msg += lengthprefixed("last_known_block_number") + "\x02" + struct.pack("<Q", 0)
        msg += lengthprefixed("last_known_block_time") + "\x05" + lengthprefixed(time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(0)))
        msg += lengthprefixed("last_known_fork_block_number") + "\x02" + struct.pack("<Q", 0)

        self.send_message(5006, msg)
      
if len(sys.argv) != 5:
    print "Usage: fbtcclaimer.py <private key in WIF format> <public source address> <destination address> <number of satoshis to send, including fee>"
    exit()
    
wifkey = sys.argv[1]
srcaddr = sys.argv[2]
destaddr = sys.argv[3]
satoshis = int(sys.argv[4])
fee = 1000

tx = generate_tx(wifkey, srcaddr, destaddr, satoshis, fee)

h = hashlib.new("ripemd160")
h.update(tx)
txnetid = h.digest()

print "YOU ARE ABOUT TO SEND %.8f FBTC FROM %s TO %s!" % ((satoshis - fee) / 100000000.0, srcaddr, destaddr)
print "!!!EVERYTHING ELSE WILL BE EATEN UP AS FEES! CONTINUE AT YOUR OWN RISK!!!"

get_consent("I am sending coins on the Fast Bitcoin network and I accept the risks")

seed_nodes = ("47.74.233.132", "47.74.232.61", "47.88.222.217", "47.72.233.73", "47.74.230.248")

tcp = STCP()
tcp.connect((random.choice(seed_nodes), 40032))

while True:
    msgtype, msg = tcp.recv_message()
    
    if msgtype == 5006:
        print "received hello_message"
        tcp.send_hello()
        tcp.send_message(5007, "")

    if msgtype == 5003:
        print "received fetch_blockchain_item_ids_message"
        itemtype, numitems = struct.unpack("<IB", msg[0:5])
        tcp.send_message(5002, struct.pack("<II", 0, 1001) + "\x00")
        
        print "advertising my transaction"
        tcp.send_message(5001, struct.pack("<I", 1000) + "\x01" + txnetid)
        
    if msgtype == 5004:
        print "received fetch_items_message"
        print "sending my transaction"
        tcp.send_message(1000, tx)
        tcp.send_message(5004, struct.pack("<I", 1000) + "\x01" + txnetid)
                
    if msgtype == 5005:
        print "received item_not_available_message, TX PROBABLY INVALID"
        exit()
        
    if msgtype == 5009:
        print "received address_request_message"
        tcp.send_message(5010, "\x00")
        
    if msgtype == 5012:
        print "received current_time_request_message"
        ts = int(time.time() * 1000000)
        tcp.send_message(5013, struct.pack("<QQQ", ts, ts, ts))

    if msgtype == 1000:
        print "received trx_message"
        if msg == tx:
            print "OUR TRANSACTION WAS ACCEPTED! YES!"
            exit()
            
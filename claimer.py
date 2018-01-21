import hashlib, os, struct, sys, socket, time

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

def der_signature(r, s):
    r = long2byte(r)
    if ord(r[0]) >= 0x80:
        r = "\x00" + r
        
    s = long2byte(s)
    if ord(s[0]) >= 0x80:
        s = "\x00" + s
    
    res = "\x02" + chr(len(r)) + r + "\x02" + chr(len(s)) + s
    return "\x30" + chr(len(res)) + res
    
def signdata(privkey, data):
    h = hashlib.sha256(hashlib.sha256(data).digest()).digest()
    z = byte2long(h)
    r, s = sign(privkey, z)
    return der_signature(r, s)
    
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
    if s > (R / 2):
        s = R - s
    
    return r, s
    
def serializepubkey(p, compressed):
    if compressed:
        if p.y & 1 == 1:
            return "\x03" + long2byte(p.x, 32)
        else:
            return "\x02" + long2byte(p.x, 32)
    else:
        return "\x04" + long2byte(p.x, 32) + long2byte(p.y, 32)

def pubkey2h160(p, compressed):
    s = serializepubkey(p, compressed)
    s = hashlib.sha256(s).digest()
    h = hashlib.new("ripemd160")
    h.update(s)
    return h.digest()
    
def pubkey2addr(p, compressed):
    s = pubkey2h160(p, compressed)
    return b58encode("\x00" + s)
    
def wif2privkey(s):
    s = b58decode(s)
    assert s.startswith("\x80")
    
    if len(s) == 34 and s[-1] == "\x01":
        return byte2long(s[1:33]), 1
        
    assert len(s) == 33
    return byte2long(s[1:33]), 0
    
def recv_all(s, length):
    ret = ""
    while len(ret) < length:
        temp = s.recv(length - len(ret))
        if len(temp) == 0:
            raise "Connection reset!"
        ret += temp
        
    return ret
    
class Client(object):
    def __init__(self, address):
        self.address = address
        
    def connect(self):
        self.sc = socket.create_connection(self.address)
        print "connected"
        
    def send(self, cmd, msg):
        magic = struct.pack("<L", 0xe6d4e2fa)
        wrapper = magic + cmd.ljust(12, "\x00") + struct.pack("<L", len(msg)) + hashlib.sha256(hashlib.sha256(msg).digest()).digest()[0:4] + msg
        self.sc.sendall(wrapper)
        print "sent", repr(cmd)
        
    def recv_msg(self):
        header = recv_all(self.sc, 24)
        
        if len(header) != 24:
            print "INVALID HEADER LENGTH", repr(head)
            exit()

        cmd = header[4:16].rstrip("\x00")
        payloadlen = struct.unpack("<I", header[16:20])[0]
        payload = recv_all(self.sc, payloadlen)
        return cmd, payload
        
def maketx(sourcetx, sourceidx, wifkey, targetaddr, numsatoshi, originalsatoshi):
    sourceprivkey, compressed = wif2privkey(wifkey)
    sourcepubkey = scalar_mul(sourceprivkey, Point(gx, gy), N)
    sourceh160 = pubkey2h160(sourcepubkey, compressed)
    targeth160 = b58decode(targetaddr)[1:]

    s  = struct.pack("<I", 2)
    s += chr(1)                             # one input
    s += sourcetx.decode("hex")[::-1]       # source TX is in little endian order
    s += struct.pack("<I", sourceidx)       # source ID too
    s += "[[SCRIPT]]"                       # placeholder for script
    s += "\xff\xff\xff\xff"                 # no locktime
    s += chr(1)                             # one output
    s += struct.pack("<Q", numsatoshi)      # hope you got this number correctly!
    s += "\x19\x76\xa9\x14" + targeth160 + "\x88\xac" # standard P2PKH script
    s += "\x00\x00\x00\x00"                 # no locktime
    
    to_sign = ""
    to_sign += struct.pack("<I", 2)
    to_sign += hashlib.sha256(hashlib.sha256(sourcetx.decode("hex")[::-1] + struct.pack("<I", sourceidx)).digest()).digest()
    to_sign += hashlib.sha256(hashlib.sha256("\xff\xff\xff\xff" ).digest()).digest()
    to_sign += sourcetx.decode("hex")[::-1] + struct.pack("<I", sourceidx)
    to_sign += "\x19\x76\xa9\x14" + sourceh160 + "\x88\xac"
    to_sign += struct.pack("<Q", originalsatoshi)
    to_sign += "\xff\xff\xff\xff"
    to_sign += hashlib.sha256(hashlib.sha256(struct.pack("<Q", numsatoshi) + "\x19\x76\xa9\x14" + targeth160 + "\x88\xac").digest()).digest()
    to_sign += "\x00\x00\x00\x00"
    to_sign += struct.pack("<I", 0x41 | (70 << 8))
    
    signature = signdata(sourceprivkey, to_sign) + "\x41"
    serpubkey = serializepubkey(sourcepubkey, compressed)

    script = chr(len(signature)) + signature + chr(len(serpubkey)) + serpubkey
    script = chr(len(script)) + script

    tx = s.replace("[[SCRIPT]]", script)

    return tx, pubkey2addr(sourcepubkey, compressed)

if len(sys.argv) != 7:
    print "Usage: b2x.py <source TXID> <source index> <source WIF private key> <target address> <number of satoshis>"
    print "example: b2x.py 4adc427d330497992710feaa32f85c389ef5106f74e7006878bd14b54500dfff 0 5K2YUVmWfxbmvsNxCsfvArXdGXm7d5DC9pn4yD75k2UaSYgkXTh 1aa5cmqmvQq8YQTEqcTmW7dfBNuFwgdCD 1853"
else:
    sourcetx = sys.argv[1]
    sourceidx = int(sys.argv[2])
    wifkey = sys.argv[3]
    targetaddr = sys.argv[4]
    numsatoshi = int(sys.argv[5])
    originalsatoshi = int(sys.argv[6])
    
    tx, sourceaddr = maketx(sourcetx, sourceidx, wifkey, targetaddr, numsatoshi, originalsatoshi)
    print "YOU ARE ABOUT TO SEND %.8f BTF FROM %s TO %s!" % (numsatoshi / 100000000.0, sourceaddr, targetaddr)
    print "!!!EVERYTHING ELSE WILL BE EATEN UP AS FEES! CONTINUE AT YOUR OWN RISK!!!"
    print "Write 'I understand' to continue"
    
    answer = raw_input()
    assert answer == "I understand"
    
    txhash = hashlib.sha256(hashlib.sha256(tx).digest()).digest()[::-1]
    print "generated transaction", txhash.encode("hex")
    
    client = Client(("b.btf.hjy.cc", 8346))
    client.connect()
    
    versionno = 70015
    services = 0
    localaddr = "\x00" * 8 + "00000000000000000000FFFF".decode("hex") + "\x00" * 6
    nonce = os.urandom(8)
    user_agent = "Scraper"
    msg = struct.pack("<IQQ", versionno, services, int(time.time())) + localaddr + localaddr + nonce + chr(len(user_agent)) + user_agent + struct.pack("<IB", 0, 0)
    client.send("version", msg)

    while True:
        cmd, payload = client.recv_msg()
        if cmd == "version":
            print repr(payload)
            client.send("verack", "")
            
        elif cmd == "ping":
            client.send("pong", payload)
            client.send("inv", "\x01" + struct.pack("<I", 1) + txhash)
            
        elif cmd == "getdata":
            if payload == "\x01\x01\x00\x00\x00" + txhash:
                print "sending txhash, if there is no error response everything probably went well"
                client.send("tx", tx)
                
        else:
            print repr(cmd)
            print repr(payload)
            print

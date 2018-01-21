import hashlib, os, struct, sys, socket, time, urllib2, json, argparse, cStringIO

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

def read_varint(st):
    value = ord(st.read(1))
    if value < 0xfd:
        return value
    if value == 0xfd:
        return struct.unpack("<H", st.read(2))[0]
    if value == 0xfe:
        return struct.unpack("<L", st.read(4))[0]
    if value == 0xff:
        return struct.unpack("<Q", st.read(8))[0]
        
def make_varint(value):
    if value < 0xfd:
        return chr(value)
    if value <= 0xffff:
        return "\xfd" + struct.pack("<H", value)
    if value <= 0xffffffff:
        return "\xfe" + struct.pack("<L", value)
    
    return "\xff" + struct.pack("<Q", value)

def lengthprefixed(s):
    return make_varint(len(s)) + s
    
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
    
    res = "\x02" + lengthprefixed(r) + "\x02" + lengthprefixed(s)
    return "\x30" + lengthprefixed(res)
    
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

def doublesha(s):
    s = hashlib.sha256(s).digest()
    return hashlib.sha256(s).digest()

def hash160(s):
    s = hashlib.sha256(s).digest()
    h = hashlib.new("ripemd160")
    h.update(s)
    return h.digest()

def pubkey2h160(p, compressed):
    s = serializepubkey(p, compressed)
    return hash160(s)
    
def pubkey2segwith160(p):
    s = pubkey2h160(p, 1)
    return hash160("\x00\x14" + s)
    
def pubkey2addr(p, compressed):
    s = pubkey2h160(p, compressed)
    return b58encode("\x00" + s)
    
def pubkey2segwitaddr(p):
    s = pubkey2segwith160(p)
    return b58encode("\x05" + s)
    
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
    
def identify_keytype(wifkey, addr):
    addrh160 = b58decode(addr)[1:]
    assert len(addrh160) == 20

    privkeytype, privkey, compressed = wif2privkey(args.wifkey)
    pubkey = scalar_mul(privkey, Point(gx, gy), N)
    if addrh160 == pubkey2h160(pubkey, 0):
        return "standard", privkey, pubkey, addrh160, 0
        
    if addrh160 == pubkey2h160(pubkey, 1):
        return "standard", privkey, pubkey, addrh160, 1
        
    if addrh160 == pubkey2segwith160(pubkey):
        return "segwit", privkey, pubkey, addrh160, 1
        
    raise Exception("Unable to identify key type!")

def get_tx_details_from_blockchaininfo(txid, addr):
    res = urllib2.urlopen("https://blockchain.info/rawtx/%s" % txid)
    txinfo = json.loads(res.read())
    found = None
    for outinfo in txinfo["out"]:
        if outinfo["addr"] == addr:
            txindex = outinfo["n"]
            script = outinfo["script"].decode("hex")
            satoshis = outinfo["value"]
            print "Candidate transaction, index %d with %d Satoshis (%.8f BTC)" % (txindex, satoshis, satoshis / 100000000.0)
            if found is None:
                found = txindex, script, satoshis
            else:
                raise Exception("Multiple outputs with that address found! Aborting!")
                
    if not found:
        raise Exception("No output with address %s found in transaction %s" % (addr, txid))
        
    return found
    
def recv_all(s, length):
    ret = ""
    while len(ret) < length:
        temp = s.recv(length - len(ret))
        if len(temp) == 0:
            raise "Connection reset!"
        ret += temp
        
    return ret
    
class Client(object):
    def __init__(self, coin):
        self.coin = coin
        
    def connect(self):
        address = (coin.seeds[ord(os.urandom(1)) % len(coin.seeds)], coin.port)
        self.sc = socket.create_connection(address)
        print "connected to", address
        
    def send(self, cmd, msg):
        magic = struct.pack("<L", coin.magic)
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
        
class BitcoinFork(object):
    def __init__(self):
        pass
        
    def maketx_standard_p2pkh(self, sourcetx, sourceidx, sourcescript, sourcesatoshis, sourceprivkey, pubkey, compressed, targetaddr, fee):
        targeth160 = b58decode(targetaddr)[1:]
        
        version = struct.pack("<I", 1)
        prevout = sourcetx.decode("hex")[::-1] + struct.pack("<I", sourceidx)
        sequence = struct.pack("<i", -1)
        inscript = lengthprefixed(sourcescript)
        satoshis = struct.pack("<Q", sourcesatoshis)
        locktime = struct.pack("<I", 0)
        sigtype = struct.pack("<I", self.signid)
        outscript = struct.pack("<Q", sourcesatoshis - fee) + lengthprefixed("\x76\xa9\x14" + targeth160 + "\x88\xac")
        
        to_sign = version + doublesha(prevout) + doublesha(sequence) + prevout + inscript + satoshis + sequence + doublesha(outscript) + locktime + sigtype
        
        signature = signdata(sourceprivkey, to_sign) + make_varint(self.signtype)
        serpubkey = serializepubkey(pubkey, compressed)

        script = lengthprefixed(signature) + lengthprefixed(serpubkey)
        script = lengthprefixed(script)
        
        tx = version + make_varint(1) + prevout + script + sequence + make_varint(1) + outscript + locktime
        return tx
        
class BitcoinFaith(BitcoinFork):
    def __init__(self):
        self.ticker = "BTF"
        self.fullname = "Bitcoin Faith"
        self.magic = 0xe6d4e2fa
        self.port = 8346
        self.seeds = ("a.btf.hjy.cc", "b.btf.hjy.cc", "c.btf.hjy.cc", "d.btf.hjy.cc", "e.btf.hjy.cc", "f.btf.hjy.cc")
        self.signtype = 0x41
        self.signid = self.signtype | (70 << 8)
        
def maketx(sourcetx, sourceidx, wifkey, targetaddr, numsatoshi, originalsatoshi):
    sourceprivkeytype, sourceprivkey, compressed = wif2privkey(wifkey)
    sourcepubkey = scalar_mul(sourceprivkey, Point(gx, gy), N)
    sourceh160 = pubkey2h160(sourcepubkey, compressed)
    targeth160 = b58decode(targetaddr)[1:]

    s  = struct.pack("<I", 1)
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
    to_sign += struct.pack("<I", 1)
    to_sign += hashlib.sha256(hashlib.sha256(sourcetx.decode("hex")[::-1] + struct.pack("<I", sourceidx)).digest()).digest()
    to_sign += hashlib.sha256(hashlib.sha256("\xff\xff\xff\xff" ).digest()).digest()
    to_sign += sourcetx.decode("hex")[::-1] + struct.pack("<I", sourceidx)
    to_sign += "\x19\x76\xa9\x14" + sourceh160 + "\x88\xac"
    to_sign += struct.pack("<Q", originalsatoshi)
    to_sign += "\xff\xff\xff\xff"
    to_sign += hashlib.sha256(hashlib.sha256(struct.pack("<Q", numsatoshi) + "\x19\x76\xa9\x14" + targeth160 + "\x88\xac").digest()).digest()
    to_sign += "\x00\x00\x00\x00"
    to_sign += struct.pack("<I", 0x41 | (70 << 8))
    print to_sign.encode("hex")
    print hashlib.sha256(to_sign).hexdigest()
    
    signature = signdata(sourceprivkey, to_sign) + "\x41"
    serpubkey = serializepubkey(sourcepubkey, compressed)

    script = chr(len(signature)) + signature + chr(len(serpubkey)) + serpubkey
    script = chr(len(script)) + script

    tx = s.replace("[[SCRIPT]]", script)
    print tx.encode("hex")
    return tx, pubkey2addr(sourcepubkey, compressed)

parser = argparse.ArgumentParser()
parser.add_argument("txid", help="Transaction ID with the source of the coins")
parser.add_argument("wifkey", help="Private key of the coins to be claimed in WIF (wallet import) format")
parser.add_argument("srcaddr", help="Source address of the coins")
parser.add_argument("destaddr", help="Destination address of the coins")
parser.add_argument("--fee", help="Fee measured in Satoshis, default is 1000", type=int, default=1000)
parser.add_argument("--txindex", help="Manually specified txindex, skips blockchain.info API query", type=int)
parser.add_argument("--satoshis", help="Manually specified number of satoshis, skips blockchain.info API query", type=int)
args = parser.parse_args()

keytype, privkey, pubkey, sourceh160, compressed = identify_keytype(args.wifkey, args.srcaddr)
if keytype == "standard":
    script = "\x76\xa9\x14" + sourceh160 + "\x88\xac"
else:
    raise Exception("Not impl!")
    
if args.txindex and args.satoshis:
    txindex, satoshis = args.txindex, args.satoshis
else:
    txindex, bciscript, satoshis = get_tx_details_from_blockchaininfo(args.txid, args.srcaddr)
    assert bciscript == script

coin = BitcoinFaith()
tx = coin.maketx_standard_p2pkh(args.txid, txindex, script, satoshis, privkey, pubkey, compressed, args.destaddr, args.fee)
print "Raw transaction"
print tx.encode("hex")
print
print "YOU ARE ABOUT TO SEND %.8f BTF FROM %s TO %s!" % ((satoshis - args.fee) / 100000000.0, args.srcaddr, args.destaddr)
print "!!!EVERYTHING ELSE WILL BE EATEN UP AS FEES! CONTINUE AT YOUR OWN RISK!!!"
print "Write 'I understand' to continue"

answer = raw_input()
assert answer == "I understand"

txhash = hashlib.sha256(hashlib.sha256(tx).digest()).digest()
print "generated transaction", txhash[::-1].encode("hex")

client = Client(coin)
client.connect()

versionno = 70015
services = 0
localaddr = "\x00" * 8 + "00000000000000000000FFFF".decode("hex") + "\x00" * 6
nonce = os.urandom(8)
user_agent = "Scraper"
msg = struct.pack("<IQQ", versionno, services, int(time.time())) + localaddr + localaddr + nonce + lengthprefixed(user_agent) + struct.pack("<IB", 0, 0)
client.send("version", msg)

while True:
    cmd, payload = client.recv_msg()
    print "received", cmd, "size", len(payload)
    if cmd == "version":
        client.send("verack", "")
        
    elif cmd == "ping":
        client.send("pong", payload)
        client.send("inv", "\x01" + struct.pack("<I", 1) + txhash)
        client.send("mempool", "")
        
    elif cmd == "getdata":
        if payload == "\x01\x01\x00\x00\x00" + txhash:
            print "sending txhash, if there is no error response everything probably went well"
            client.send("tx", tx)
         
    elif cmd == "feefilter":
        minfee = struct.unpack("<Q", payload)[0]
        print "server requires minimum fee of %d satoshis" % minfee
        if minfee <= args.fee:
            print "our fee is larger or equal, it should be OK"
        else:
            print "OUR FEE IS TOO SMALL, transaction might not be accepted"
            
    elif cmd == "inv":
        blocks_to_get = []
        st = cStringIO.StringIO(payload)
        ninv = read_varint(st)
        for i in xrange(ninv):
            invtype = struct.unpack("<I", st.read(4))[0]
            invhash = st.read(32)
            
            if invtype == 1:
                if invhash == txhash:
                    print "OUR TRANSACTION IS IN THEIR MEMPOOL, TRANSACTION ACCEPTED! YAY!"
            elif invtype == 2:
                blocks_to_get.append(invhash)
                
        if len(blocks_to_get) > 0:
            inv = ["\x02\x00\x00\x00" + invhash for invhash in blocks_to_get]
            msg = lengthprefixed("".join(inv))
            client.send("getdata", msg)
        
    elif cmd == "block":
        if tx in payload:
            print "BLOCK WITH OUR TRANSACTION OBSERVED! YES!"
            
    else:
        print repr(cmd), repr(payload)

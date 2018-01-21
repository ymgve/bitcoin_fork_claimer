import hashlib, os, struct, sys, socket, time, urllib2, json, argparse, cStringIO, traceback

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
        return "segwit", privkey, pubkey, pubkey2h160(pubkey, 1), 1
        
    raise Exception("Unable to identify key type!")

def get_tx_details_from_blockchaininfo(txid, addr):
    print "Querying blockchain.info API about data for transaction %s" % txid
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
    
def get_consent(consentstring):
    print "Write '%s' to continue" % consentstring

    answer = raw_input()
    if answer != consentstring:
        raise Exception("User did not write '%s', aborting" % consentstring)

def recv_all(s, length):
    ret = ""
    while len(ret) < length:
        temp = s.recv(length - len(ret))
        if len(temp) == 0:
            raise Exception("Connection reset!")
        ret += temp
        
    return ret
    
class Client(object):
    def __init__(self, coin):
        self.coin = coin
        
    def connect(self):
        index = ord(os.urandom(1)) % len(coin.seeds)
        while True:
            try:
                address = (coin.seeds[index], coin.port)
                print "trying to connect to", address
                self.sc = socket.create_connection(address)
                print "connected to", address
                break
            except:
                traceback.print_exc()
                index = (index + 1) % len(coin.seeds)
        
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
        self.coinratio = 1.0
        self.versionno = 70015
        
    def maketx_segwitsig(self, sourcetx, sourceidx, sourceh160, sourcesatoshis, sourceprivkey, pubkey, compressed, outscript, fee, is_segwit=False):
        version = struct.pack("<I", 1)
        prevout = sourcetx.decode("hex")[::-1] + struct.pack("<I", sourceidx)
        sequence = struct.pack("<i", -1)
        inscript = lengthprefixed("\x76\xa9\x14" + sourceh160 + "\x88\xac")
        satoshis = struct.pack("<Q", sourcesatoshis)
        txout = struct.pack("<Q", sourcesatoshis - fee) + lengthprefixed(outscript)
        locktime = struct.pack("<I", 0)
        sigtype = struct.pack("<I", self.signid)
        
        to_sign = version + doublesha(prevout) + doublesha(sequence) + prevout + inscript + satoshis + sequence + doublesha(txout) + locktime + sigtype
        
        signature = signdata(sourceprivkey, to_sign) + make_varint(self.signtype)
        serpubkey = serializepubkey(pubkey, compressed)
        sigblock = lengthprefixed(signature) + lengthprefixed(serpubkey)

        if not is_segwit:
            script = lengthprefixed(sigblock)
        else:
            script = "\x17\x16\x00\x14" + sourceh160
            
        plaintx = version + make_varint(1) + prevout + script + sequence + make_varint(1) + txout + locktime
        
        if not is_segwit:
            return tx, doublesha(tx)
        else:
            tx = version + "\x00\x01" + plaintx[4:-4] + "\x02" + sigblock + locktime
            return tx, doublesha(plaintx)
        
class BitcoinFaith(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BTF"
        self.fullname = "Bitcoin Faith"
        self.magic = 0xe6d4e2fa
        self.port = 8346
        self.seeds = ("a.btf.hjy.cc", "b.btf.hjy.cc", "c.btf.hjy.cc", "d.btf.hjy.cc", "e.btf.hjy.cc", "f.btf.hjy.cc")
        self.signtype = 0x41
        self.signid = self.signtype | (70 << 8)
        self.PUBKEY_ADDRESS = chr(36)
        self.SCRIPT_ADDRESS = chr(40)

class BitcoinWorld(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BTW"
        self.fullname = "Bitcoin World"
        self.magic = 0x777462f8
        self.port = 8357
        self.seeds = ("47.52.250.221",)
        self.signtype = 0x41
        self.signid = self.signtype | (87 << 8)
        self.coinratio = 10000.0
        self.PUBKEY_ADDRESS = chr(73)
        self.SCRIPT_ADDRESS = chr(31)

class BitcoinGold(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BTG"
        self.fullname = "Bitcoin Gold"
        self.magic = 0x446d47e1
        self.port = 8338
        self.seeds = ("pool-us.bloxstor.com", "btgminingusa.com", "btg1.stage.bitsane.com", "eu-dnsseed.bitcoingold-official.org", "dnsseed.bitcoingold.org", "dnsseed.btcgpu.org")
        self.signtype = 0x41
        self.signid = self.signtype | (79 << 8)
        self.PUBKEY_ADDRESS = chr(38)
        self.SCRIPT_ADDRESS = chr(23)

parser = argparse.ArgumentParser()
parser.add_argument("cointicker", help="Coin type", choices=["BTF", "BTW", "BTG"])
parser.add_argument("txid", help="Transaction ID with the source of the coins")
parser.add_argument("wifkey", help="Private key of the coins to be claimed in WIF (wallet import) format")
parser.add_argument("srcaddr", help="Source address of the coins")
parser.add_argument("destaddr", help="Destination address of the coins")
parser.add_argument("--fee", help="Fee measured in Satoshis, default is 1000", type=int, default=1000)
parser.add_argument("--txindex", help="Manually specified txindex, skips blockchain.info API query", type=int)
parser.add_argument("--satoshis", help="Manually specified number of satoshis, skips blockchain.info API query", type=int)
args = parser.parse_args()

if args.cointicker == "BTF":
    coin = BitcoinFaith()
if args.cointicker == "BTW":
    coin = BitcoinWorld()
if args.cointicker == "BTG":
    coin = BitcoinGold()
    
keytype, privkey, pubkey, sourceh160, compressed = identify_keytype(args.wifkey, args.srcaddr)

if args.txindex is not None and args.satoshis is not None:
    txindex, satoshis = args.txindex, args.satoshis
else:
    txindex, bciscript, satoshis = get_tx_details_from_blockchaininfo(args.txid, args.srcaddr)
    
    if keytype == "standard":
        script = "\x76\xa9\x14" + sourceh160 + "\x88\xac"
    elif keytype == "segwit":
        script = "\xa9\x14" + hash160("\x00\x14" + sourceh160) + "\x87"
    else:
        raise Exception("Not implemented!")
    
    if bciscript != script:
        raise Exception("Script type in source output that is not supported!")

addr = b58decode(args.destaddr)
assert len(addr) == 21
if addr[0] == "\x00" or addr[0] == coin.PUBKEY_ADDRESS:
    outscript = "\x76\xa9\x14" + addr[1:] + "\x88\xac"
elif addr[0] == "\x05" or addr[0] == coin.SCRIPT_ADDRESS:
    print "YOU ARE TRYING TO SEND TO A P2SH ADDRESS! THIS IS NOT NORMAL! Are you sure you know what you're doing?"
    get_consent("I am aware that the destination address is P2SH")
    outscript = "\xa9\x14" + addr[1:] + "\x87"
else:
    raise Exception("The destination address %s does not match BTC or %s. Are you sure you got the right one?" % (args.destaddr, coin.ticker))

if keytype in ("standard", "segwit"):
    tx, txhash = coin.maketx_segwitsig(args.txid, txindex, sourceh160, satoshis, privkey, pubkey, compressed, outscript, args.fee, keytype == "segwit")
else:
    raise Exception("Not implemented!")
    
print "Raw transaction"
print tx.encode("hex")
print

coinamount = (satoshis - args.fee) * coin.coinratio / 100000000.0
btcamount = (satoshis - args.fee) / 100000000.0
print "YOU ARE ABOUT TO SEND %.8f %s (equivalent to %.8f BTC) FROM %s TO %s!" % (coinamount, coin.ticker, btcamount, args.srcaddr, args.destaddr)
print "!!!EVERYTHING ELSE WILL BE EATEN UP AS FEES! CONTINUE AT YOUR OWN RISK!!!"
get_consent("I am sending coins on the %s network and I accept the risks" % coin.fullname)

print "generated transaction", txhash[::-1].encode("hex")

client = Client(coin)
client.connect()

services = 0
localaddr = "\x00" * 8 + "00000000000000000000FFFF".decode("hex") + "\x00" * 6
nonce = os.urandom(8)
user_agent = "Scraper"
msg = struct.pack("<IQQ", coin.versionno, services, int(time.time())) + localaddr + localaddr + nonce + lengthprefixed(user_agent) + struct.pack("<IB", 0, 0)
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
            print "sending txhash"
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
            msg = make_varint(len(inv)) + "".join(inv)
            client.send("getdata", msg)
        
    elif cmd == "block":
        if tx in payload:
            print "BLOCK WITH OUR TRANSACTION OBSERVED! YES!"
            
    elif cmd == "addr":
        st = cStringIO.StringIO(payload)
        naddr = read_varint(st)
        for i in xrange(naddr):
            data = st.read(30)
            if data[12:24] == "\x00" * 10 + "\xff\xff":
                print "got peer ipv4 address %d.%d.%d.%d port %d" % struct.unpack(">BBBBH", data[24:30])
            else:
                print "got peer ipv6 address %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x port %d" % struct.unpack(">HHHHHHHHH", data[12:30])
        
    else:
        print repr(cmd), repr(payload)

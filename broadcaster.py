import hashlib, os, struct, sys, socket, time, urllib2, json, argparse, cStringIO, traceback, hmac, ssl

N = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fL
R = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141L
A = 0L
B = 7L
gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798L
gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8L

b58ab = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
bech32ab = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = (chk >> 25)
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk

def bech32_hrp_expand(s):
    return [ord(x) >> 5 for x in s] + [0] + [ord(x) & 31 for x in s]

def bech32decode(addr):
    hrp, data = addr.lower().rsplit("1", 1)
    data = [bech32ab.index(c) for c in data]

    assert bech32_polymod(bech32_hrp_expand(hrp) + data) == 1, "bech32 checksum failed"
    assert data[0] == 0, "only support version 0 witness for now"
    data = data[1:-6]
    
    n = 0
    for c in data:
        n = n << 5 | c

    nbytes, extrabits = divmod(len(data) * 5, 8)
    return long2byte(n >> extrabits, nbytes)
  
def bech32encode(hrp, s):
    extrabits = (5 - ((len(s) * 8) % 5)) % 5
    nchars = (len(s) * 8 + extrabits) / 5
    n = byte2long(s) << extrabits
    
    data = []
    for i in xrange(nchars):
        data.insert(0, n & 31)
        n >>= 5
        
    data.insert(0, 0) # version 0
    
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0,0,0,0,0,0]) ^ 1
    data += [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(bech32ab[c] for c in data)
  
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
    
def gen_k_rfc6979(privkey, m):
    h1 = hashlib.sha256(m).digest()
    x = long2byte(privkey, 32)
    V = "\x01" * 32
    K = "\x00" * 32
    K = hmac.new(K, V + "\x00" + x + h1, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    K = hmac.new(K, V + "\x01" + x + h1, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    
    while True:
        V = hmac.new(K, V, hashlib.sha256).digest()
        k = byte2long(V)
        if k >= 1 and k < R:
            return k
        
        K = hmac.new(K, V + "\x00", hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()
    
def signdata(privkey, data):
    h = doublesha(data)
    r, s = sign(privkey, h)
    return der_signature(r, s)
    
def sign(privkey, h):
    z = byte2long(h)
    k = gen_k_rfc6979(privkey, h)
    
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
    if addr.startswith("bc1"):
        addrh160 = bech32decode(addr)
        assert len(addrh160) == 20
        
        privkeytype, privkey, compressed = wif2privkey(args.wifkey)
        pubkey = scalar_mul(privkey, Point(gx, gy), N)
        if addrh160 == pubkey2h160(pubkey, 1):
            return "segwitbech32", privkey, pubkey, addrh160, 1
        
        raise Exception("Unable to identify key type!")
    else:
        addrh160 = b58decode(addr)[-20:]
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

def get_tx_details_from_blockchaininfo(txid, addr, hardforkheight):
    print "Querying blockchain.info API about data for transaction %s" % txid
    res = urllib2.urlopen("https://blockchain.info/rawtx/%s" % txid)
    txinfo = json.loads(res.read())
    if hardforkheight < txinfo["block_height"]:
        print "\n\nTHIS TRANSACTION HAPPENED AFTER THE COIN FORKED FROM THE MAIN CHAIN!"
        print "(fork at height %d, this tx at %d)" % (hardforkheight, txinfo["block_height"])
        print "You will most likely be unable to claim these coins."
        print "Please look for an earlier transaction before the fork point.\n\n"
        get_consent("I will try anyway")
        
    found = None
    for outinfo in txinfo["out"]:
        if "addr" in outinfo and outinfo["addr"] == addr:
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
    
def get_btx_details_from_chainz_cryptoid(addr):
    print "Querying chainz.cryptoid.info about last unspent transaction for address"
    url = "https://chainz.cryptoid.info/btx/api.dws?q=unspent&active=%s&key=a660e3112b78" % addr

    request = urllib2.Request(url)
    request.add_header('User-Agent', 'Mozilla/5.0')
    opener = urllib2.build_opener() 
    res = opener.open(request)
    
    txinfo = json.loads(res.read())
    unspent_outputs = txinfo["unspent_outputs"]
    if len(unspent_outputs) == 0:
        raise Exception("Block explorer didn't find any coins at that address")
    
    outinfo = unspent_outputs[0]
    txid = outinfo["tx_hash"]
    txindex = outinfo["tx_ouput_n"]
    script = outinfo["script"].decode("hex")
    satoshis = int(outinfo["value"])
    
    return txid, txindex, script, satoshis

def get_coin_details_from_electrum(coin, targettxid, sourceh160, keytype):
    if keytype in ("segwit", "segwit_btcp"):
        addr = b58encode(coin.SCRIPT_ADDRESS + hash160("\x00\x14" + sourceh160))
    else:
        addr = b58encode(coin.PUBKEY_ADDRESS + sourceh160)

    sc = socket.create_connection((coin.electrum_server, coin.electrum_port))
    if coin.electrum_ssl:
        sc = ssl.wrap_socket(sc)
    sc.send('{ "id": 0, "method": "blockchain.address.listunspent", "params": [ "%s" ] }\n' % addr)
    res = readline(sc)
        
    j = json.loads(res)
    unspents = j["result"]
    if len(unspents) == 0:
        raise Exception("No %s at this address!" % coin.ticker)
    
    if len(unspents) == 1:
        target = unspents[0]
    else:
        target = None
        for tx in unspents:
            if tx["tx_hash"] == targettxid:
                target = tx
                break
                
        if target is None:
            print "Multiple potential outputs possible - please use one of these TXIDs to claim"
            for tx in unspents:
                coinamount = int(tx["value"]) * coin.coinratio / 100000000.0
                btcamount = int(tx["value"]) / 100000000.0
                print "    TXID %s : %20.8f %s (equivalent to %.8f BTC)" % (tx["tx_hash"], coinamount, coin.ticker, btcamount)
                
            exit()

    
    return target["tx_hash"], int(target["tx_pos"]), None, int(target["value"])

def readline(sc):
    res = ""
    while True:
        c = sc.recv(1)
        if c == "":
            raise Exception("Disconnect when querying electrum server")
        elif c == "\n":
            break
        else:
            res += c
    
    return res

def get_consent(consentstring):
    print "\nWrite '%s' to continue" % consentstring

    answer = raw_input()
    #if answer != consentstring:
    #    raise Exception("User did not write '%s', aborting" % consentstring)

class Client(object):
    
    _MAX_MEMPOOL_CHECKS = 5
    _MAX_CONNECTION_RETRIES = 100
    
    def __init__(self, coin):
        self.coin = coin
        self._transaction_sent = False
        self._transaction_accepted = None
        self._mempool_check_count = 0
        self._connection_retries = 0
        
    def send(self, cmd, msg):
        magic = struct.pack("<L", self.coin.magic)
        wrapper = magic + cmd.ljust(12, "\x00") + struct.pack("<L", len(msg)) + hashlib.sha256(hashlib.sha256(msg).digest()).digest()[0:4] + msg
        self.sc.sendall(wrapper)
        print "---> %s (%d bytes)" % (repr(cmd), len(msg))
        
    def recv_msg(self):
        def recv_all(length):
            ret = ""
            while len(ret) < length:
                temp = self.sc.recv(length - len(ret))
                if len(temp) == 0:
                    raise socket.error("Connection reset!")
                ret += temp
            return ret

        header = recv_all(24)
        if len(header) != 24:
            raise Exception("INVALID HEADER LENGTH\n%s" % repr(header))

        cmd = header[4:16].rstrip("\x00")
        payloadlen = struct.unpack("<I", header[16:20])[0]
        payload = recv_all(payloadlen)
        return cmd, payload
        
    def send_tx(self, txhash, tx):
        serverindex = ord(os.urandom(1)) % len(self.coin.seeds)
        txhash_hexfmt = txhash[::-1].encode("hex")
        while True:
            try:
                address = (coin.seeds[serverindex], self.coin.port)
                print "Connecting to", address, "...",
                self.sc = socket.create_connection(address, 10)
                print "SUCCESS, connected to", self.sc.getpeername()
                self.sc.settimeout(120)
                
                services = 0
                localaddr = "\x00" * 8 + "00000000000000000000FFFF".decode("hex") + "\x00" * 6
                nonce = os.urandom(8)
                user_agent = "Scraper"
                msg = struct.pack("<IQQ", self.coin.versionno, services, int(time.time())) + (
                    localaddr + localaddr + nonce + lengthprefixed(user_agent) + struct.pack("<IB", 0, 0))
                client.send("version", msg)

                while True:
                    cmd, payload = client.recv_msg()
                    print "<--- '%s' (%d bytes)" % (cmd, len(payload))
                    if cmd == "version":
                        sio = cStringIO.StringIO(payload)
                        protoversion, services, timestamp = struct.unpack("<IQQ", sio.read(20))
                        addr_recv = sio.read(26)
                        addr_from = sio.read(26)
                        nonce = sio.read(8)
                        user_agent_len = read_varint(sio)
                        user_agent = sio.read(user_agent_len)
                        start_height = struct.unpack("<I", sio.read(4))[0]
                        print "     Version information:"
                        print "\tprotocol version", protoversion
                        print "\tservices", services
                        print "\ttimestamp", time.asctime(time.gmtime(timestamp))
                        print "\tuser agent", repr(user_agent)
                        print "\tblock height", repr(start_height)
                        client.send("verack", "")
                        
                    elif cmd == "sendheaders":
                        msg = make_varint(0)
                        client.send("headers", msg)
                        
                    elif cmd == "ping":
                        client.send("pong", payload)

                        if not self._transaction_sent:
                            client.send("inv", "\x01" + struct.pack("<I", 1) + txhash)
                        elif not self._transaction_accepted:
                            client.send("tx", tx)
                            print "\tRe-sent transaction: %s" % txhash_hexfmt

                        client.send("mempool", "")
                        
                    elif cmd == "getdata":
                        if payload == "\x01\x01\x00\x00\x00" + txhash:
                            print "\tPeer requesting transaction details for %s" % txhash_hexfmt
                            client.send("tx", tx)
                            print "\tSENT TRANSACTION: %s" % txhash_hexfmt
                            self._transaction_sent = True

                        # If a getdata comes in without our txhash, it generally means the tx was rejected.
                        elif self._transaction_sent:
                            print "\tReceived getdata without our txhash. The transaction may have been rejected."
                            print "\tThis script will retransmit the transaction and monitor the mempool for a few minutes before giving up."
                         
                    elif cmd == "feefilter":
                        minfee = struct.unpack("<Q", payload)[0]
                        print "\tserver requires minimum fee of %d satoshis" % minfee
                            
                    elif cmd == "inv":
                        blocks_to_get = []
                        st = cStringIO.StringIO(payload)
                        ninv = read_varint(st)
                        transaction_found = False
                        invtypes = {1: 'transaction', 2: 'block'}
                        for i in xrange(ninv):
                            invtype = struct.unpack("<I", st.read(4))[0]
                            invhash = st.read(32)
                            invtypestr = invtypes[invtype] if invtype in invtypes else str(invtype)

                            if i < 10:
                                print "\t%s: %s" % (invtypestr, invhash[::-1].encode("hex"))
                            elif i == 10:
                                print "\t..."
                                print "\tNot printing additional %d transactions" % (ninv - i)
                            
                            if invtype == 1:
                                if invhash == txhash:
                                    transaction_found = True
                            elif invtype == 2:
                                blocks_to_get.append(invhash)
                        if transaction_found and not self._transaction_accepted:        
                            print "\n\tOUR TRANSACTION IS IN THEIR MEMPOOL, TRANSACTION ACCEPTED! YAY!"
                            if args.noblock:
                            # User specified --noblock, we are done here
                                return
                            else:
                                print "\tConsider leaving this script running until it detects the transaction in a block."
                            self._transaction_accepted = True
                        elif transaction_found:
                            print "\tTransaction still in mempool. Continue waiting for block inclusion."
                        elif not blocks_to_get:
                            print "\n\tOur transaction was not found in the mempool."
                            self._mempool_check_count += 1
                            if self._mempool_check_count <= self._MAX_MEMPOOL_CHECKS:
                                print "\tWill retransmit and check again %d more times." % (self._MAX_MEMPOOL_CHECKS - self._mempool_check_count)
                            else:
                                raise Exception("\tGiving up on transaction. Please verify that the inputs have not already been spent.")

                        if blocks_to_get:
                            inv = ["\x02\x00\x00\x00" + invhash for invhash in blocks_to_get]
                            msg = make_varint(len(inv)) + "".join(inv)
                            client.send("getdata", msg)
                            print "\trequesting %d blocks" % len(blocks_to_get)
                        
                    elif cmd == "block":
                        if tx in payload or plaintx in payload:
                            print "\tBLOCK WITH OUR TRANSACTION OBSERVED! YES!"
                            print "\tYour coins have been successfully sent. Exiting..."
                            return
                        else:
                            print "\tTransaction not included in observed block."
                            
                    elif cmd == "addr":
                        st = cStringIO.StringIO(payload)
                        naddr = read_varint(st)
                        for _ in xrange(naddr):
                            data = st.read(30)
                            if data[12:24] == "\x00" * 10 + "\xff\xff":
                                address = "%d.%d.%d.%d:%d" % struct.unpack(">BBBBH", data[24:30])
                            else:
                                address = "[%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x]:%d" % struct.unpack(">HHHHHHHHH", data[12:30])
                            print "\tGot peer address: %s" % address
                    elif cmd not in ('sendcmpct', 'verack'):
                        print repr(cmd), repr(payload)
                
            except (socket.error, socket.herror, socket.gaierror, socket.timeout) as e:
                if self._connection_retries >= self._MAX_CONNECTION_RETRIES:
                    raise
                print "\tConnection failed with: %s" % repr(e)
                print "\tWill retry %d more times." % (self._MAX_CONNECTION_RETRIES - self._connection_retries)
                serverindex = (serverindex + 1) % len(self.coin.seeds)
                self._connection_retries += 1
                time.sleep(2)

    
class BitcoinFork(object):
    def __init__(self):
        self.coinratio = 1.0
        self.versionno = 70015
        self.maketx = self.maketx_segwitsig
        self.extrabytes = ""
        self.BCDgarbage = ""
        self.BCLsalt = ""
        self.txversion = 1
        self.signtype = 0x01
        self.signid = self.signtype
        self.PUBKEY_ADDRESS = chr(0)
        self.SCRIPT_ADDRESS = chr(5)
        self.bch_fork = False
        self.address_size = 21
        self.electrum_server = None
        
    def maketx_segwitsig(self, sourcetx, sourceidx, sourceh160, signscript, sourcesatoshis, sourceprivkey, pubkey, compressed, outputs, fee, keytype):
        verifytotal = fee
        
        version = struct.pack("<I", self.txversion)
        prevout = sourcetx.decode("hex")[::-1] + struct.pack("<I", sourceidx)
        sequence = struct.pack("<i", -1)
        inscript = lengthprefixed(signscript)
        satoshis = struct.pack("<Q", sourcesatoshis)
        
        txouts = ""
        for outscript, amount, destaddr, rawaddr in outputs:
            txouts += struct.pack("<Q", amount) + lengthprefixed(outscript)
            verifytotal += amount
        
        locktime = struct.pack("<I", 0)
        sigtype = struct.pack("<I", self.signid)
        
        prevouthash = doublesha(prevout)
        sequencehash = doublesha(sequence)
        txoutshash = doublesha(txouts)
        
        to_sign = version + self.BCDgarbage + self.BCLsalt + prevouthash + sequencehash + prevout + inscript + satoshis + sequence + txoutshash + locktime + sigtype + self.extrabytes
        
        signature = signdata(sourceprivkey, to_sign) + make_varint(self.signtype)
        serpubkey = serializepubkey(pubkey, compressed)

        if keytype == "p2pk":
            sigblock = lengthprefixed(signature)
        else:
            sigblock = lengthprefixed(signature) + lengthprefixed(serpubkey)

        if keytype in ("p2pk", "standard"):
            script = lengthprefixed(sigblock)
        elif keytype == "segwit":
            script = "\x17\x16\x00\x14" + sourceh160
        elif keytype == "segwitbech32":
            script = "\x00"
        else:
            raise Exception("Not implemented!")
            
        plaintx = version + self.BCDgarbage + make_varint(1) + prevout + script + sequence + make_varint(len(outputs)) + txouts + locktime
        
        if verifytotal != sourcesatoshis:
            raise Exception("Addition of output amounts does not match input amount (Bug?), aborting")
            
        if keytype in ("p2pk", "standard"):
            return plaintx, plaintx
        else:
            witnesstx = version + self.BCDgarbage + "\x00\x01" + plaintx[4+len(self.BCDgarbage):-4] + "\x02" + sigblock + locktime
            return witnesstx, plaintx
        
    def maketx_basicsig(self, sourcetx, sourceidx, sourceh160, signscript, sourcesatoshis, sourceprivkey, pubkey, compressed, outputs, fee, keytype):
        if keytype in ("segwit", "segwitbech32"):
            return self.maketx_segwitsig(sourcetx, sourceidx, sourceh160, signscript, sourcesatoshis, sourceprivkey, pubkey, compressed, outputs, fee, keytype)
            
        verifytotal = fee
        
        version = struct.pack("<I", self.txversion)
        prevout = sourcetx.decode("hex")[::-1] + struct.pack("<I", sourceidx)
        sequence = struct.pack("<i", -1)
        inscript = lengthprefixed(signscript)
        
        txouts = ""
        for outscript, amount, destaddr, rawaddr in outputs:
            txouts += struct.pack("<Q", amount) + lengthprefixed(outscript)
            verifytotal += amount
        
        locktime = struct.pack("<I", 0)
        sigtype = struct.pack("<I", self.signid)
        
        to_sign = version + self.BCDgarbage + make_varint(1) + prevout + inscript + sequence + make_varint(len(outputs)) + txouts + locktime + sigtype + self.extrabytes + self.BCLsalt
        
        signature = signdata(sourceprivkey, to_sign) + make_varint(self.signtype)
        serpubkey = serializepubkey(pubkey, compressed)
        
        if keytype == "p2pk":
            sigblock = lengthprefixed(signature)
        else:
            sigblock = lengthprefixed(signature) + lengthprefixed(serpubkey)
            
        if keytype == "segwit_btcp":
            sigblock += lengthprefixed("\x00\x14" + sourceh160)
        
        plaintx = version + self.BCDgarbage + make_varint(1) + prevout + lengthprefixed(sigblock) + sequence + make_varint(len(outputs)) + txouts + locktime
        
        if verifytotal != sourcesatoshis:
            raise Exception("Addition of output amounts does not match input amount (Bug?), aborting")
            
        return plaintx, plaintx
        
class BitcoinFaith(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BTF"
        self.fullname = "Bitcoin Faith"
        self.hardforkheight = 500000
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
        self.hardforkheight = 499777
        self.magic = 0x777462f8
        self.port = 8357
        self.seeds = ("47.52.250.221", "47.91.237.5")
        self.signtype = 0x41
        self.signid = self.signtype | (87 << 8)
        self.PUBKEY_ADDRESS = chr(73)
        self.SCRIPT_ADDRESS = chr(31)
        self.coinratio = 10000.0

class BitcoinGold(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BTG"
        self.fullname = "Bitcoin Gold"
        self.hardforkheight = 491407
        self.magic = 0x446d47e1
        self.port = 8338
        self.seeds = ("pool-us.bloxstor.com", "btgminingusa.com", "btg1.stage.bitsane.com", "eu-dnsseed.bitcoingold-official.org", "dnsseed.bitcoingold.org", "dnsseed.btcgpu.org")
        self.signtype = 0x41
        self.signid = self.signtype | (79 << 8)
        self.PUBKEY_ADDRESS = chr(38)
        self.SCRIPT_ADDRESS = chr(23)

class BitcoinX(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BCX"
        self.fullname = "BitcoinX"
        self.hardforkheight = 498888
        self.magic = 0xf9bc0511
        self.port = 9003
        self.seeds = ("192.169.227.48", "120.92.119.221", "120.92.89.254", "120.131.5.173", "120.92.117.145", "192.169.153.174", "192.169.154.185", "166.227.117.163")
        self.signtype = 0x11
        self.signid = self.signtype
        self.PUBKEY_ADDRESS = chr(75)
        self.SCRIPT_ADDRESS = chr(63)
        self.coinratio = 10000.0

class Bitcoin2X(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "B2X"
        self.fullname = "Bitcoin 2X Segwit"
        self.hardforkheight = 501451
        self.magic = 0xd8b5b2f4
        self.port = 8333
        self.seeds = ("node1.b2x-segwit.io", "node2.b2x-segwit.io", "node3.b2x-segwit.io")
        self.signtype = 0x31
        self.signid = self.signtype << 1
        self.maketx = self.maketx_basicsig # does not use new-style segwit signing for standard transactions

class UnitedBitcoin(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "UBTC"
        self.fullname = "United Bitcoin"
        self.hardforkheight = 498777
        self.magic = 0xd9b4bef9
        self.port = 8333
        self.seeds = ("urlelcm1.ub.com", "urlelcm2.ub.com", "urlelcm3.ub.com", "urlelcm4.ub.com", "urlelcm5.ub.com", "urlelcm6.ub.com", "urlelcm7.ub.com", "urlelcm8.ub.com", "urlelcm9.ub.com", "urlelcm10.ub.com")
        self.signtype = 0x09
        self.signid = self.signtype
        self.maketx = self.maketx_basicsig # does not use new-style segwit signing for standard transactions
        self.versionno = 731800
        self.extrabytes = "\x02ub"

# https://github.com/superbitcoin/SuperBitcoin
class SuperBitcoin(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "SBTC"
        self.fullname = "Super Bitcoin"
        self.hardforkheight = 498888
        self.magic = 0xd9b4bef9
        self.port = 8334
        self.seeds = ("seed.superbtca.com", "seed.superbtca.info", "seed.superbtc.org")
        self.signtype = 0x41
        self.signid = self.signtype
        self.maketx = self.maketx_basicsig # does not use new-style segwit signing for standard transactions
        self.extrabytes = lengthprefixed("sbtc")
        self.versionno = 70017
        
class BitcoinDiamond(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BCD"
        self.fullname = "Bitcoin Diamond"
        self.hardforkheight = 495866
        self.magic = 0xd9b4debd
        self.port = 7117
        self.seeds = ("seed1.dns.btcd.io", "139.198.190.221", "seed2.dns.btcd.io", "121.201.13.117", "seed3.dns.btcd.io", "139.198.12.140",
                      "seed4.dns.btcd.io", "52.52.113.134", "seed5.dns.btcd.io", "13.114.121.21", "seed6.dns.btcd.io", "52.78.28.110")
        self.signtype = 0x01
        self.signid = self.signtype
        self.maketx = self.maketx_basicsig # does not use new-style segwit signing for standard transactions
        self.txversion = 12
        self.BCDgarbage = "\xff" * 32
        self.coinratio = 10.0
        
class BitcoinPizza(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BPA"
        self.fullname = "Bitcoin Pizza"
        self.hardforkheight = 501888
        self.magic = 0xd9c4bea9
        self.port = 8888
        self.seeds = ("dnsseed.bitcoinpizza.cc", "seed1.bitcoinpizza.cc", "seed2.bitcoinpizza.cc", "seed3.bitcoinpizza.cc", "seed4.bitcoinpizza.cc")
        self.signtype = 0x21
        self.signid = self.signtype | (47 << 8)
        self.PUBKEY_ADDRESS = chr(55)
        self.SCRIPT_ADDRESS = chr(80)

class BitcoinNew(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BTN"
        self.fullname = "Bitcoin New"
        self.hardforkheight = 501000
        self.magic = 0x344d37a1
        self.port = 8838
        self.seeds = ("dnsseed.bitcoin-new.org",)
        self.signtype = 0x41
        self.signid = self.signtype | (88 << 8)

class BitcoinHot(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BTH"
        self.fullname = "Bitcoin Hot"
        self.hardforkheight = 498848
        self.magic = 0x04ad77d1
        self.port = 8222
        self.seeds = ("seed-us.bitcoinhot.co", "seed-jp.bitcoinhot.co", "seed-hk.bitcoinhot.co", "seed-uk.bitcoinhot.co", "seed-cn.bitcoinhot.co")
        self.signtype = 0x41
        self.signid = self.signtype | (53 << 8)
        self.PUBKEY_ADDRESS = chr(40)
        self.SCRIPT_ADDRESS = chr(5) # NOT CERTAIN
        self.versionno = 70016
        self.coinratio = 100.0

# https://github.com/bitcoinvote/bitcoin
class BitcoinVote(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BTV"
        self.fullname = "Bitcoin Vote"
        self.hardforkheight = 505050
        self.magic = 0x505050f9
        self.port = 8333
        self.seeds = ("seed1.bitvote.one", "seed2.bitvote.one", "seed3.bitvote.one")
        self.signtype = 0x41
        self.signid = self.signtype | (50 << 8)
        self.maketx = self.maketx_basicsig # does not use new-style segwit signing for standard transactions

class BitcoinTop(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BTT"
        self.fullname = "Bitcoin Top"
        self.hardforkheight = 501118
        self.magic = 0xd0b4bef9
        self.port = 18888
        self.seeds = ("dnsseed.bitcointop.org", "seed.bitcointop.org", "worldseed.bitcointop.org", "dnsseed.bitcointop.group", "seed.bitcointop.group",
            "worldseed.bitcointop.group", "dnsseed.bitcointop.club", "seed.bitcointop.club", "worldseed.bitcointop.club")
        self.signtype = 0x01
        self.signid = self.signtype
        self.maketx = self.maketx_basicsig # does not use new-style segwit signing for standard transactions
        self.txversion = 13
        self.BCDgarbage = "\xff" * 32

class BitCore(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BTX"
        self.fullname = "BitCore"
        self.hardforkheight = 492820
        self.magic = 0xd9b4bef9
        self.port = 8555
        self.seeds = ("37.120.190.76", "37.120.186.85", "185.194.140.60", "188.71.223.206", "185.194.142.122")
        self.signtype = 0x01
        self.signid = self.signtype
        self.maketx = self.maketx_basicsig # does not use new-style segwit signing for standard transactions
        
class BitcoinPay(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BTP"
        self.fullname = "Bitcoin Pay"
        self.hardforkheight = 499345
        self.magic = 0xd9c1d0fe
        self.port = 8380
        self.seeds = ("seed.btceasypay.com",)
        self.signtype = 0x41
        self.signid = self.signtype | (80 << 8)
        self.PUBKEY_ADDRESS = chr(0x38)
        self.SCRIPT_ADDRESS = chr(0x3a)
        self.coinratio = 10.0

# https://github.com/btcking/btcking
class BitcoinKing(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BCK"
        self.fullname = "Bitcoin King"
        self.hardforkheight = 499999
        self.magic = 0x161632af
        self.port = 16333
        self.seeds = ("47.52.28.49",)
        self.signtype = 0x41
        self.signid = self.signtype | (143 << 8)
        
# https://github.com/bitcoincandyofficial/bitcoincandy
class BitcoinCandy(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "CDY"
        self.fullname = "Bitcoin Candy"
        self.hardforkheight = 512666
        self.magic = 0xd9c4c3e3
        self.port = 8367
        self.seeds = ("seed.bitcoincandy.one", "seed.cdy.one")
        self.signtype = 0x41
        self.signid = self.signtype | (111 << 8)
        self.PUBKEY_ADDRESS = chr(0x1c)
        self.SCRIPT_ADDRESS = chr(0x58)
        self.coinratio = 1000.0
        self.bch_fork = True

# https://github.com/BTSQ/BitcoinCommunity
class BitcoinCommunity(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BTSQ"
        self.fullname = "Bitcoin Community"
        self.hardforkheight = 506066
        self.magic = 0xd9c4ceb9
        self.port = 8866
        self.seeds = ("dnsseed.aliyinke.com", "seed1.aliyinke.com", "seed2.aliyinke.com", "seed3.aliyinke.com")
        self.signtype = 0x11
        self.signid = self.signtype | (31 << 8)
        self.PUBKEY_ADDRESS = chr(63)
        self.SCRIPT_ADDRESS = chr(58)
        self.coinratio = 1000.0

# https://github.com/worldbitcoin/worldbitcoin
class WorldBitcoin(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "WBTC"
        self.fullname = "World Bitcoin"
        self.hardforkheight = 503888
        self.magic = 0xd9b4bef9
        self.port = 8338
        self.seeds = ("dnsseed.btcteams.net", "dnsseed.wbtcteam.org")
        self.signtype = 0x41
        self.signid = self.signtype
        self.extrabytes = lengthprefixed("wbtc")
        self.maketx = self.maketx_basicsig

# https://github.com/bitcoincashplus/bitcoincashplus
class BitcoinCashPlus(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BCP"
        self.fullname = "Bitcoin Cash Plus"
        self.hardforkheight = 509696
        self.magic = 0xe1476d44
        self.port = 8337
        self.seeds = ("seed.bcpfork.org", "seed.bcpseeds.net", "seed.bitcoincashplus.org")
        self.signtype = 0x41
        self.signid = self.signtype
        self.PUBKEY_ADDRESS = chr(28)
        self.SCRIPT_ADDRESS = chr(23)
        self.bch_fork = True

# https://github.com/Bitcoin-ABC/bitcoin-abc
class BitcoinCash(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BCH"
        self.fullname = "Bitcoin Cash"
        self.hardforkheight = 478559
        self.magic = 0xe8f3e1e3
        self.port = 8333
        self.seeds = ("seed.bitcoinabc.org", "seed-abc.bitcoinforks.org", "seed.bitprim.org", "seed.deadalnix.me", "seeder.criptolayer.net")
        self.signtype = 0x41
        self.signid = self.signtype
        self.bch_fork = True

# https://github.com/BTCPrivate/BitcoinPrivate
class BitcoinPrivate(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BTCP"
        self.fullname = "Bitcoin Private"
        self.hardforkheight = 511346
        self.magic = 0xcda2eaa8
        self.port = 7933
        self.seeds = ("dnsseed.btcprivate.co",)
        self.signtype = 0x41
        self.signid = self.signtype | (42 << 8)
        self.PUBKEY_ADDRESS = "\x13\x25"
        self.SCRIPT_ADDRESS = "\x13\xaf"
        self.address_size = 22
        self.maketx = self.maketx_basicsig
        self.versionno = 180003
        self.electrum_server = "electrum.btcprivate.org"
        self.electrum_port = 5222
        self.electrum_ssl = True
        self.electrum_pushtx = False

# https://github.com/bitcoin-atom/bitcoin-atom
class BitcoinAtom(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BCA"
        self.fullname = "Bitcoin Atom"
        self.hardforkheight = 505888
        self.magic = 0xe81dc14f
        self.port = 7333
        self.seeds = ("seed.bitcoinatom.io", "seed.bitcoin-atom.org", "seed.bitcoinatom.net")
        self.signtype = 0x41
        self.signid = self.signtype | (93 << 8)
        self.PUBKEY_ADDRESS = chr(23)
        self.SCRIPT_ADDRESS = chr(10)

# https://github.com/lbtcio/lbtc-core
class LightningBitcoin(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "LBTC"
        self.fullname = "Lightning Bitcoin"
        self.hardforkheight = 499999
        self.magic = 0xd5b3bef9
        self.port = 9333
        self.seeds = ("seed1.lbtc.io", "seed2.lbtc.io", "seed3.lbtc.io", "seed4.lbtc.io", "seed5.lbtc.io", "seed6.lbtc.io", "seed7.lbtc.io", "seed8.lbtc.io", "seed9.lbtc.io", "seed10.lbtc.io")
        self.signtype = 0x01
        self.signid = self.signtype
        self.PUBKEY_ADDRESS = chr(0)
        self.SCRIPT_ADDRESS = chr(5)
        self.txversion = 0xff02             # https://github.com/lbtcio/lbtc-core/blob/bdf916128dd6f60340e5f3404cab2f7836c0b2f4/src/primitives/transaction.h#L307
        self.maketx = self.maketx_basicsig
        self.extrabytes = lengthprefixed("LBTC")

# https://github.com/bitunity/BitClassicCoin-BICC
class BitcoinClassicCoin(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BICC"
        self.fullname = "BitClassic Coin"
        self.hardforkheight = 498888
        self.magic = 0xd9b4bef9
        self.port = 8666
        self.seeds = ("47.104.59.46", "47.104.59.9")
        self.signtype = 0x11
        self.signid = self.signtype
        self.maketx = self.maketx_basicsig
        self.versionno = 731800
        self.extrabytes = lengthprefixed("111")

# https://github.com/BitcoinInterestOfficial/BitcoinInterest
class BitcoinInterest(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BCI"
        self.fullname = "Bitcoin Interest"
        self.hardforkheight = 505083
        self.magic = 0x26fee4ed
        self.port = 8334
        self.seeds = ("seeder1.bci-server.com", "seeder2.bci-server.com", "seeder3.bci-server.com", "37.16.104.241")
        self.signtype = 0x41
        self.signid = self.signtype | (79 << 8)
        self.PUBKEY_ADDRESS = chr(102)
        self.SCRIPT_ADDRESS = chr(23)

# https://github.com/cleanblockchain/Bitcoin-CBC
class BitcoinCBC(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BCBC"
        self.fullname = "Bitcoin@CBC"
        self.hardforkheight = 498754
        self.magic = 0xd9b4bef9
        self.port = 8341
        self.seeds = ("btcseed.cleanblockchain.io", "btcseed.cleanblockchain.org")
        self.maketx = self.maketx_basicsig

# BTCH is a Komodo (source code at https://github.com/SuperNETorg/komodo) "alternate" blockchain
# Komodo alternate chains basically just use a different network magic and TCP port, calculated from the ticker name and coin amount

# We use the BTCH Electrum server to get details and submit transactions, so most of these parameters aren't used (but they are correct)
# Server details from https://github.com/SuperNETorg/Agama/blob/master/routes/electrumjs/electrumServers.js
class BitcoinHush(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BTCH"
        self.fullname = "Bitcoin Hush"
        self.hardforkheight = 507089
        self.magic = 0xff5e1cf4 # calculated from ticker name and supply: hex(zlib.crc32(struct.pack("<Q", 20998641) + "BTCH") & 0xffffffff)
        self.port = 8799 # calculated from magic: 0xff5e1cf4 % 7777 + 8000
        self.seeds = ("seeds.komodoplatform.com", "seeds.komodo.mewhub.com")
        self.maketx = self.maketx_basicsig
        self.versionno = 170002
        self.PUBKEY_ADDRESS = chr(60)
        self.SCRIPT_ADDRESS = chr(85)
        self.electrum_server = "electrum1.cipig.net"
        self.electrum_port = 10020
        self.electrum_ssl = False
        self.electrum_pushtx = True

# https://github.com/BitcoinGod/BitcoinGod
class BitcoinGod(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "GOD"
        self.fullname = "Bitcoin God"
        self.hardforkheight = 501226
        self.magic = 0xd9b4bef9
        self.port = 8885
        self.seeds = ("s.bitcoingod.org",)
        self.maketx = self.maketx_basicsig
        self.signtype = 0x01 | 0x08
        self.signid = self.signtype | (107 << 8)
        self.PUBKEY_ADDRESS = chr(97)
        self.SCRIPT_ADDRESS = chr(23)

class BigBitcoin(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BBC"
        self.fullname = "Big Bitcoin"
        self.hardforkheight = 508888
        self.magic = 0xc3c2c2fe
        self.port = 8366
        self.seeds = ("seed.bigbitcoins.org",)
        self.signtype = 0x41
        self.signid = self.signtype | (66 << 8)
        self.PUBKEY_ADDRESS = chr(0x19)
        self.SCRIPT_ADDRESS = chr(0x55)
        self.coinratio = 10.0

class NewBitcoin(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "NBTC"
        self.fullname = "NewBitcoin"
        self.hardforkheight = 501225
        self.magic = 0xd8b4bef9
        self.port = 18880
        self.seeds = ("1.newbitcoin.org", "2.newbitcoin.org", "3.newbitcoin.org", "4.newbitcoin.org", "1.manghao.com", "2.manghao.com", "3.manghao.com", "4.manghao.com")
        self.signtype = 0x41
        self.signid = self.signtype | (78 << 8)
        self.coinratio = 2.0

# https://github.com/bitcoinclean/bitcoinclean
class BitcoinClean(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BCL"
        self.fullname = "BitcoinClean"
        self.hardforkheight = 518800
        self.magic = 0x4d744be4
        self.port = 8338
        self.seeds = ("seed.bitcoinclean.org",)
        self.maketx = self.maketx_basicsig
        self.signtype = 0x41
        self.signid = self.signtype
        self.BCLsalt = "c003700e0c31442382638363c1c7c19fc59f6f9fffcc7e4ebe67fc37781de007".decode("hex")
        
# https://github.com/bitcoin-cored/bitcoin-cored
class BitcoinCore(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BTCC"
        self.fullname = "Bitcoin Core"
        self.hardforkheight = 576698
        self.magic = 0xe8f3e1e3
        self.port = 10333
        self.seeds = ("seeder.clashic.cash", "seeder.bitcoincore.zone", "seeder-mainnet.clashic.org")
        self.signtype = 0x01 | 0x20
        self.signid = self.signtype
        self.bch_fork = True
        
# https://github.com/bitcoinfile/bitcoinfile/tree/master/bificore
class BitcoinFile(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BIFI"
        self.fullname = "BitcoinFile"
        self.hardforkheight = 501225
        self.magic = 0xd8c42ef8
        self.port = 10698
        self.seeds = ("dnsseed1.bitcoinfile.org", "dnsseed2.bitcoinfile.org", "dnsseed3.bitcoinfile.org",
                      "dnsseed4.bitcoinfile.org", "dnsseed5.bitcoinfile.org", "dnsseed6.bitcoinfile.org",
                      "dnsseed7.bitcoinfile.org", "dnsseed8.bitcoinfile.org", "dnsseed9.bitcoinfile.org")
        self.maketx = self.maketx_basicsig
        self.signtype = 0x01
        self.signid = self.signtype
        self.txversion = 20
        self.BCDgarbage = struct.pack("<I", self.txversion)
        self.coinratio = 1000.0
        
# https://github.com/MicroBitcoinOrg/MicroBitcoin
class MicroBitcoin(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "MBC"
        self.fullname = "Micro Bitcoin"
        self.hardforkheight = 525001
        self.magic = 0x7643424d
        self.port = 6403
        self.seeds = ("52.76.239.17", "52.220.61.181", "54.169.196.33", "13.228.235.197", "35.176.181.187", "35.177.156.222", "52.53.211.109", "13.57.248.201")
        self.maketx = self.maketx_basicsig
        self.signtype = 0x01 | 0x60
        self.signid = self.signtype
        self.coinratio = 10000.0
        self.PUBKEY_ADDRESS = chr(26)
        self.SCRIPT_ADDRESS = chr(51)

assert gen_k_rfc6979(0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721, "sample") == 0xa6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60

parser = argparse.ArgumentParser()
parser.add_argument("cointicker", help="Coin type", choices=["BTF", "BTW", "BTG", "BCX", "B2X", "UBTC", "SBTC", "BCD", "BPA", "BTN", "BTH", "BTV", "BTT", "BTX", "BTP", "BCK", "CDY", "BTSQ", "WBTC", "BCH", "BTCP", "BCA", "LBTC", "BICC", "BCI", "BCP", "BCBC", "BTCH", "GOD", "BBC", "NBTC", "BCL", "BTCC", "BIFI", "MBC"])
parser.add_argument("rawtx", help="Raw tx")

args = parser.parse_args()

if args.cointicker == "B2X":
    coin = Bitcoin2X()
elif args.cointicker == "BBC":
    coin = BigBitcoin()
elif args.cointicker == "BCA":
    coin = BitcoinAtom()
elif args.cointicker == "BCBC":
    coin = BitcoinCBC()
elif args.cointicker == "BCD":
    coin = BitcoinDiamond()
elif args.cointicker == "BCH":
    coin = BitcoinCash()
elif args.cointicker == "BCI":
    coin = BitcoinInterest()
elif args.cointicker == "BCK":
    coin = BitcoinKing()
elif args.cointicker == "BCL":
    coin = BitcoinClean()
elif args.cointicker == "BCP":
    coin = BitcoinCashPlus()
elif args.cointicker == "BCX":
    coin = BitcoinX()
elif args.cointicker == "BICC":
    coin = BitcoinClassicCoin()
elif args.cointicker == "BIFI":
    coin = BitcoinFile()
elif args.cointicker == "BPA":
    coin = BitcoinPizza()
elif args.cointicker == "BTCC":
    coin = BitcoinCore()
elif args.cointicker == "BTCH":
    coin = BitcoinHush()
elif args.cointicker == "BTCP":
    coin = BitcoinPrivate()
elif args.cointicker == "BTF":
    coin = BitcoinFaith()
elif args.cointicker == "BTG":
    coin = BitcoinGold()
elif args.cointicker == "BTH":
    coin = BitcoinHot()
elif args.cointicker == "BTN":
    coin = BitcoinNew()
elif args.cointicker == "BTP":
    coin = BitcoinPay()
elif args.cointicker == "BTSQ":
    coin = BitcoinCommunity()
elif args.cointicker == "BTT":
    coin = BitcoinTop()
elif args.cointicker == "BTV":
    coin = BitcoinVote()
elif args.cointicker == "BTW":
    coin = BitcoinWorld()
elif args.cointicker == "BTX":
    coin = BitCore()
elif args.cointicker == "CDY":
    coin = BitcoinCandy()
elif args.cointicker == "GOD":
    coin = BitcoinGod()
elif args.cointicker == "LBTC":
    coin = LightningBitcoin()
elif args.cointicker == "MBC":
    coin = MicroBitcoin()
elif args.cointicker == "NBTC":
    coin = NewBitcoin()
elif args.cointicker == "SBTC":
    coin = SuperBitcoin()
elif args.cointicker == "UBTC":
    coin = UnitedBitcoin()
elif args.cointicker == "WBTC":
    coin = WorldBitcoin()
    
plaintx = args.rawtx
tx = plaintx.decode("hex")
txhash = doublesha(plaintx)

client = Client(coin)
client.send_tx(txhash, tx)


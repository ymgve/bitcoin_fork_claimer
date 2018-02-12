import urllib2, json, argparse

def get_txs_list(addr, coin):
    res = urllib2.urlopen("https://blockchain.info/address/%s?format=json" % addr)
    txinfo = json.loads(res.read())

    total = 0
    for tx in txinfo["txs"]:
        if tx["block_height"] < coin.hardforkheight:
            for incoming in tx["inputs"]:
                if incoming["prev_out"]["addr"] == addr:
                    total -= incoming["prev_out"]["value"]
            for out in tx["out"]:
                if out["addr"] == addr:
                    total += out["value"]
                    coinamount = total * coin.coinratio / 100000000.0
                    if coinamount > 0:
                        print "Block: %s" %tx["block_height"]
                        print "Transaction: %s" %tx["hash"]
                        print "Ammount: %.8f %s" %(coinamount, coin.ticker)
                        print "Command: python2.7 claimer.py %s _PKEY_ %s _DEST_ADDR_" %(tx["hash"], addr)
    
class BitcoinFork(object):
    def __init__(self):
        self.coinratio = 1.0
        self.versionno = 70015
        self.maketx = self.maketx_segwitsig
        self.extrabytes = ""
        self.BCDgarbage = ""
        self.txversion = 1
        self.signtype = 0x01
        self.signid = self.signtype
        
    def maketx_segwitsig(self, sourcetx, sourceidx, sourceh160, signscript, sourcesatoshis, sourceprivkey, pubkey, compressed, outscript, fee, keytype):
        version = struct.pack("<I", self.txversion)
        prevout = sourcetx.decode("hex")[::-1] + struct.pack("<I", sourceidx)
        sequence = struct.pack("<i", -1)
        inscript = lengthprefixed(signscript)
        satoshis = struct.pack("<Q", sourcesatoshis)
        txout = struct.pack("<Q", sourcesatoshis - fee) + lengthprefixed(outscript)
        locktime = struct.pack("<I", 0)
        sigtype = struct.pack("<I", self.signid)
        
        to_sign = version + self.BCDgarbage + doublesha(prevout) + doublesha(sequence) + prevout + inscript + satoshis + sequence + doublesha(txout) + locktime + sigtype + self.extrabytes
        
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
            
        plaintx = version + self.BCDgarbage + make_varint(1) + prevout + script + sequence + make_varint(1) + txout + locktime
        
        if keytype in ("p2pk", "standard"):
            return plaintx, plaintx
        else:
            witnesstx = version + self.BCDgarbage + "\x00\x01" + plaintx[4+len(self.BCDgarbage):-4] + "\x02" + sigblock + locktime
            return witnesstx, plaintx
        
    def maketx_basicsig(self, sourcetx, sourceidx, sourceh160, signscript, sourcesatoshis, sourceprivkey, pubkey, compressed, outscript, fee, keytype):
        if keytype in ("segwit", "segwitbech32"):
            return self.maketx_segwitsig(sourcetx, sourceidx, sourceh160, signscript, sourcesatoshis, sourceprivkey, pubkey, compressed, outscript, fee, keytype)
            
        version = struct.pack("<I", self.txversion)
        prevout = sourcetx.decode("hex")[::-1] + struct.pack("<I", sourceidx)
        sequence = struct.pack("<i", -1)
        inscript = lengthprefixed(signscript)
        txout = struct.pack("<Q", sourcesatoshis - fee) + lengthprefixed(outscript)
        locktime = struct.pack("<I", 0)
        sigtype = struct.pack("<I", self.signid)
        
        to_sign = version + self.BCDgarbage + make_varint(1) + prevout + inscript + sequence + make_varint(1) + txout + locktime + sigtype + self.extrabytes
        
        signature = signdata(sourceprivkey, to_sign) + make_varint(self.signtype)
        serpubkey = serializepubkey(pubkey, compressed)
        
        if keytype == "p2pk":
            sigblock = lengthprefixed(signature)
        else:
            sigblock = lengthprefixed(signature) + lengthprefixed(serpubkey)
        
        plaintx = version + self.BCDgarbage + make_varint(1) + prevout + lengthprefixed(sigblock) + sequence + make_varint(1) + txout + locktime
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
        self.seeds = ("node1.b2x-segwit.io", "node2.b2x-segwit.io", "node3.b2x-segwit.io", "136.243.147.159", "136.243.171.156", "46.229.165.141", "178.32.3.12")
        self.signtype = 0x21
        self.signid = self.signtype
        self.PUBKEY_ADDRESS = chr(0)
        self.SCRIPT_ADDRESS = chr(5)
        self.maketx = self.maketx_basicsig # does not use new-style segwit signing for standard transactions
        self.versionno = 70015 | (1 << 27)

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
        self.PUBKEY_ADDRESS = chr(0)
        self.SCRIPT_ADDRESS = chr(5)
        self.maketx = self.maketx_basicsig # does not use new-style segwit signing for standard transactions
        self.versionno = 731800
        self.extrabytes = "\x02ub"

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
        self.PUBKEY_ADDRESS = chr(0)
        self.SCRIPT_ADDRESS = chr(5)
        self.maketx = self.maketx_basicsig # does not use new-style segwit signing for standard transactions
        self.extrabytes = lengthprefixed("sbtc")
        
class BitcoinDiamond(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BCD"
        self.fullname = "Bitcoin Diamond"
        self.hardforkheight = 495866
        self.magic = 0xd9b4debd
        self.port = 7117
        self.seeds = ("seed1.dns.btcd.io", "seed2.dns.btcd.io", "seed3.dns.btcd.io", "seed4.dns.btcd.io", "seed5.dns.btcd.io", "seed6.dns.btcd.io")
        self.signtype = 0x01
        self.signid = self.signtype
        self.PUBKEY_ADDRESS = chr(0)
        self.SCRIPT_ADDRESS = chr(5)
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
        self.PUBKEY_ADDRESS = chr(0)
        self.SCRIPT_ADDRESS = chr(5)

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

class BitcoinVote(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BTV"
        self.fullname = "Bitcoin Vote"
        self.hardforkheight = 505050
        self.magic = 0xd9b4bef9
        self.port = 8333
        self.seeds = ("seed1.bitvote.one", "seed2.bitvote.one", "seed3.bitvote.one")
        self.signtype = 0x65
        self.signid = self.signtype
        self.PUBKEY_ADDRESS = chr(0)
        self.SCRIPT_ADDRESS = chr(5)
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
        self.PUBKEY_ADDRESS = chr(0)
        self.SCRIPT_ADDRESS = chr(5)
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
        self.PUBKEY_ADDRESS = chr(0)
        self.SCRIPT_ADDRESS = chr(5)
        self.maketx = self.maketx_basicsig # does not use new-style segwit signing for standard transactions
        
class BitcoinPay(BitcoinFork):
    def __init__(self):
        BitcoinFork.__init__(self)
        self.ticker = "BTP"
        self.fullname = "Bitcoin Pay"
        self.hardforkheight = 499345
        self.signtype = 0x41
        self.signid = self.signtype | (80 << 8)
        self.PUBKEY_ADDRESS = chr(0x38)
        self.SCRIPT_ADDRESS = chr(5) # NOT CERTAIN
        self.coinratio = 10.0


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument("cointicker", help="Coin type", choices=["BTF", "BTW", "BTG", "BCX", "B2X", "UBTC", "SBTC", "BCD", "BPA", "BTN", "BTH", "BTV", "BTT", "BTX", "BTP"])
    parser.add_argument("srcaddr", help="Text file with addresses list separated by a line break")
    args = parser.parse_args()  


    if args.cointicker == "B2X":
        coin = Bitcoin2X()
    elif args.cointicker == "BCD":
        coin = BitcoinDiamond()
    elif args.cointicker == "BCX":
        coin = BitcoinX()
    elif args.cointicker == "BPA":
        coin = BitcoinPizza()
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
    elif args.cointicker == "BTT":
        coin = BitcoinTop()
    elif args.cointicker == "BTV":
        coin = BitcoinVote()
    elif args.cointicker == "BTW":
        coin = BitcoinWorld()
    elif args.cointicker == "BTX":
        coin = BitCore()
    elif args.cointicker == "SBTC":
        coin = SuperBitcoin()
    elif args.cointicker == "UBTC":
        coin = UnitedBitcoin()

    addresses = [address.rstrip('\n') for address in open(args.srcaddr)]

    print "Searching %s coins on addresses list\n" %coin.ticker
    for address in addresses:
        print "Address: %s" %address
        get_txs_list(address, coin)
        print "\n"
    exit()





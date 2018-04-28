import hashlib, sys

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

cointypes = {
        "BTC":  (chr(0), chr(5)),
        "BBC":  (chr(0x19), chr(0x55)),
        "BTCH": (chr(60), chr(85)),
        "BTF":  (chr(36), chr(40)),
        "BTW":  (chr(73), chr(31)),
        "BTG":  (chr(38), chr(23)),
        "BCX":  (chr(75), chr(63)),
        "BPA":  (chr(55), chr(80)),
        "BTH":  (chr(40), chr(5)),
        "BTP":  (chr(0x38), chr(5)),
        "CDY":  (chr(0x1c), chr(0x58)),
        "BTSQ": (chr(63), chr(58)),
        "BTCP": ("\x13\x25", "\x13\xaf"),
        "BCA":  (chr(23), chr(10)),
        "BCI":  (chr(102), chr(23)),
        "GOD":  (chr(97), chr(23)),
    }

if len(sys.argv) != 3:
    print "Small converter script that converts base58 addresses from one kind to another."
    print
    print "Usage: convert_address.py <address to convert> <ticker symbol of coin>"
    print "Example: convert_address.py 1HKqKTMpBTZZ8H5zcqYEWYBaaWELrDEXeE BTCP"
    print
    print "Usage: convert_address.py <address to convert> <random address of another kind>"
    print "Example: convert_address.py 1HKqKTMpBTZZ8H5zcqYEWYBaaWELrDEXeE XSmfx3pzAtVm4ujeBwyUenX9p5GbHwZF6s"
else:
    if len(sys.argv[2]) <= 4:
        srctype = b58decode(sys.argv[1])[:-20]
        srcraw = b58decode(sys.argv[1])[-20:]
        if srctype == "\x05":
            identifier = cointypes[sys.argv[2]][1]
        else:
            identifier = cointypes[sys.argv[2]][0]
    else:
        identifier = b58decode(sys.argv[2])[:-20]
        srcraw = b58decode(sys.argv[1])[-20:]
        
    print b58encode(identifier + srcraw)
    
    
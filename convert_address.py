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
    
if len(sys.argv) != 3:
    print "Small converter script that converts base58 addresses from one kind to another."
    print
    print "Usage: convert_address.py <address to convert> <random address of another kind>"
    print "Example: convert_address.py 1HKqKTMpBTZZ8H5zcqYEWYBaaWELrDEXeE XSmfx3pzAtVm4ujeBwyUenX9p5GbHwZF6s"
else:
    identifier = b58decode(sys.argv[2])[:-20]
    srcraw = b58decode(sys.argv[1])[-20:]
    print b58encode(identifier + srcraw)
    
    
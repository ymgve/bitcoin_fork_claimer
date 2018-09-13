import argparse, json, urllib2

parser = argparse.ArgumentParser()
parser.add_argument("url", help="Insight block explorer base URL, like https://explorer.bitcoininterest.io")
parser.add_argument("address", help="Address to look up")

args = parser.parse_args()

url = args.url.rstrip("/")
pagenum = 0
while True:
    res = urllib2.urlopen(url + "/api/txs?address=%s&pageNum=%d" % (args.address, pagenum))
    addrinfo = json.loads(res.read())
    for tx in addrinfo["txs"]:
        for vout in tx["vout"]:
            for addr in vout["scriptPubKey"]["addresses"]:
                if addr == args.address:
                    print "Found transaction, txid %s txindex %d value %s" % (tx["txid"], vout["n"], vout["value"])

    pagenum += 1
    if "pagesTotal" not in addrinfo or int(addrinfo["pagesTotal"]) >= pagenum:
        break

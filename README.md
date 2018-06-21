!!! UPDATE TO THE LATEST VERSION IF YOU WANT TO CLAIM WBTC - MAJOR BUG FIXED !!!

This is a small script that enables you to transfer/claim various coins in Bitcoin forks
without downloading the full blockchains or messing with the official clients.

Requires Python 2.7

The following coins are recognized, although may not be fully tested:

*  B2X - [Segwit 2X](https://b2x-segwit.io/)
*  BBC - [Big Bitcoin](http://bigbitcoins.org/)
*  BCA - [Bitcoin Atom](https://bitcoinatom.io/)
*  BCBC - [Bitcoin@CBC](https://cleanblockchain.org/)
*  BCD - [Bitcoin Diamond](http://www.btcd.io/)
*  BCH - [Bitcoin Cash](https://www.bitcoincash.org/)
*  BCI - [Bitcoin Interest](http://bitcoininterest.io/)
*  BCK - [Bitcoin King](https://btcking.org/) - NOT A TRUE FORK, NOT CLAIMABLE AT THE MOMENT
*  BCL - [BitcoinClean](https://bitcoinclean.org/)
*  BCP - [Bitcoin Cash Plus](http://www.bitcoincashplus.org/)
*  BCX - [Bitcoin X](https://bcx.org/)
*  BICC - [BitClassic Coin](http://bicc.io/)
*  BIFI - [Bitcoin File](https://www.bitcoinfile.org)
*  BPA - [Bitcoin Pizza](http://p.top/en/index.html)
*  BTCC - [Bitcoin Core](https://bitcoincore.cm/)
*  BTCH - [Bitcoin Hush](http://btchush.org/)
*  BTCP - [Bitcoin Private](https://btcprivate.org/)
*  BTF - [Bitcoin Faith](http://bitcoinfaith.org/)
*  BTG - [Bitcoin Gold](https://bitcoingold.org/)
*  BTH - [Bitcoin Hot](https://www.bithot.org/)
*  BTN - [Bitcoin New](http://btn.kim/)
*  BTP - [Bitcoin Pay](http://www.btceasypay.com/)
*  BTSQ - [Bitcoin Community](http://btsq.top/)
*  BTT - [Bitcoin Top](https://bitcointop.org/)
*  BTV - [Bitcoin Vote](https://bitvote.one/)
*  BTW - [Bitcoin World](http://www.btw.one/)
*  BTX - [Bitcore](https://bitcore.cc/)
*  CDY - [Bitcoin Candy](https://cdy.one/) - Forked from Bitcoin Cash, not Bitcoin
*  GOD - [Bitcoin God](https://www.bitcoingod.org/)
*  LBTC - [Lightning Bitcoin](http://lbtc.io/)
*  NBTC - [NewBitcoin](http://www.newbitcoin.org/index_en.html)
*  SBTC - [Super Bitcoin](http://superbtc.org/)
*  UBTC - [United Bitcoin](https://www.ub.com/)
*  WBTC - [World Bitcoin](http://www.wbtcteam.org/)

At the moment it supports standard P2PKH and Segwit P2SH-P2WPKH addresses. Segwit mode has been verified to work with these coins: BTG, BCX, B2X, UBTC, BTF, BTW, SBTC, BCD, BPA, BTN, BTH, BTV, BTT, BTP, BTSQ, WBTC, BCA, BICC, BCI, BTCP, BCL, BIFI

It also has experimental support for bech32 P2WPKH, but this has only been tested on the BTG, BTN, BCD, BTH, BTV, BTT, BTP, BTSQ, WBTC, BCA, BICC, BCI, BCL networks so far.

It should support old-style Pay-2-Public-Key that were in use in 2009-2010 (use command line switch --p2pk) but this is UNTESTED at the moment.

USAGE OF THIS SCRIPT IS RISKY AND IF YOU MISTYPE ANYTHING YOU CAN LOSE ALL YOUR COINS

It has two modes of operation - blockchain.info assisted mode and standalone mode.
* In blockchain.info mode it uses the blockchain.info API to query and validate information about the transaction you're spending from.
This only works for transferring/claiming coins that existed on the BTC main chain pre-fork.
* In standalone mode the user provides all the information including transaction source output index and the number of satoshis in the source output - there is no verification done, but this mode allows you to transfer coins that are entirely on-fork.

blockchain.info mode:

    claimer.py <cointype> <source transaction ID> <source private key> <source address> <destination address>
    claimer.py BTG 4adc427d330497992710feaa32f85c389ef5106f74e7006878bd14b54500dfff 5K2YUVmWfxbmvsNxCsfvArXdGXm7d5DC9pn4yD75k2UaSYgkXTh 1HKqKTMpBTZZ8H5zcqYEWYBaaWELrDEXeE 1aa5cmqmvQq8YQTEqcTmW7dfBNuFwgdCD

Standalone mode:

    claimer.py <cointype> <source transaction ID> <source private key> <source address> <destination address> --txindex <output index in transaction> --satoshis <number of satoshis on the source transaction output>
    claimer.py BTG 4adc427d330497992710feaa32f85c389ef5106f74e7006878bd14b54500dfff 5K2YUVmWfxbmvsNxCsfvArXdGXm7d5DC9pn4yD75k2UaSYgkXTh 1HKqKTMpBTZZ8H5zcqYEWYBaaWELrDEXeE 1aa5cmqmvQq8YQTEqcTmW7dfBNuFwgdCD --txindex 0 --satoshis 3053

Default fee is set to 1000 satoshis, but can be changed with the `--fee` option.

You can specify multiple destination addresses in the destination address field, the format is:

    <address>[,<address>][,<address>][,<address>]...

where `<address>` is either a plain address or an address plus an amount in satoshis, separated by a colon. Examples:

    13PuTPQjuZ5Vh1RCrTLqYK79scG2T45LGB
    13PuTPQjuZ5Vh1RCrTLqYK79scG2T45LGB:1000000
    13PuTPQjuZ5Vh1RCrTLqYK79scG2T45LGB:1000000,1HKqKTMpBTZZ8H5zcqYEWYBaaWELrDEXeE
    13PuTPQjuZ5Vh1RCrTLqYK79scG2T45LGB:1000000,1HKqKTMpBTZZ8H5zcqYEWYBaaWELrDEXeE:1000000
    13PuTPQjuZ5Vh1RCrTLqYK79scG2T45LGB,1HKqKTMpBTZZ8H5zcqYEWYBaaWELrDEXeE:1000000

One of the destination addresses can be without a specified amount, which makes all the remaining coins (minus the fee) go to that address.

Full example:

    claimer.py BTG db4f2348b92b4cd34675df66b49855e66869d7e98eb97141e85b558c28390fb3 5K2YUVmWfxbmvsNxCsfvArXdGXm7d5DC9pn4yD75k2UaSYgkXTh 1HKqKTMpBTZZ8H5zcqYEWYBaaWELrDEXeE 13PuTPQjuZ5Vh1RCrTLqYK79scG2T45LGB:1000000,1HKqKTMpBTZZ8H5zcqYEWYBaaWELrDEXeE:1000000

USAGE OF THIS SCRIPT IS RISKY AND IF YOU MISTYPE ANYTHING YOU CAN LOSE ALL YOUR COINS

Advanced parameters for usage with scripting

`--force` - Normally, the script creates the transaction and then requires the user to manually verify and enter a string to signal consent, before submitting the transaction to the network. When this flag is used, it skips this step and automatically submits it. Use only when you know what you are doing.

`--noblock` - Without this flag, the script waits until the transaction is included in the next block. If you have a lot of addresses and use a script to process them, this can take a long time. When this flag is set, the script will finish after the transaction is included in the target network mempool. It's useful in combination with the `--force` parameter, because it allows mass processing of many addresses in an automated way.

---

There is another python script for claiming FBTC (Fast Bitcoin). The FBTC network is based on the BitShares codebase, so it does not support Segwit. There are no TXIDs or change addresses,
and you can transfer arbitrary amounts from an address multiple times.

Usage:

    fbtcclaimer.py <private key in WIF format> <public source address> <destination address> <number of satoshis to send, including fee>
    fbtcclaimer.py 5K2YUVmWfxbmvsNxCsfvArXdGXm7d5DC9pn4yD75k2UaSYgkXTh 1HKqKTMpBTZZ8H5zcqYEWYBaaWELrDEXeE 1aa5cmqmvQq8YQTEqcTmW7dfBNuFwgdCD 3053

fbtcclaimer.py also requires aes.py to be in the same folder as the script. Thanks to https://github.com/ricmoo/pyaes for the implementation.

---

Any donations can be sent to BTC address `1HDW5sy8trGE8mEKUtNacLPGCx1WRtebnp`

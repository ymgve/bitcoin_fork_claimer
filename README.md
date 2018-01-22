This is a small script that enables you to transfer/claim various coins in Bitcoin forks
without downloading the full blockchains or messing with the official clients.

Requires Python 2.7

At the moment it supports standard P2PKH and Segwit P2SH-P2WPKH addresses. Segwit mode has been verified to work with these coins: BTG, BCX, B2X, UBTC, BTF, BTW, SBTC, BCD, BPA

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

USAGE OF THIS SCRIPT IS RISKY AND IF YOU MISTYPE ANYTHING YOU CAN LOSE ALL YOUR COINS

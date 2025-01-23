wget https://bitcoincore.org/bin/bitcoin-core-28.0/bitcoin-28.0-x86_64-linux-gnu.tar.gz > /dev/null 2>&1
tar -xzvf bitcoin-28.0-x86_64-linux-gnu.tar.gz > /dev/null 2>&1
ln -s $PWD/bitcoin-28.0/bin/* /usr/local/bin/ > /dev/null 2>&1
bitcoind -daemon -signet -signetchallenge=0014499f05f4ce7bb60222487cf331b91aad6952ef2b -blocksonly=1 -addnode=178.128.153.52:11312 
bitcoin-cli --version
while true; do
    blockcount=$(bitcoin-cli -signet getblockcount)
    if [[ $blockcount -ge 300 ]]; then
        echo "blocks: $blockcount"
        break
    else
        sleep 1
    fi
done
hash=$(bitcoin-cli -signet getblockhash 301)
bitcoin-cli -signet invalidateblock $hash
echo invalidating block: $hash
echo $(bitcoin-cli -signet getblockcount)
echo $(bitcoin-cli --version)
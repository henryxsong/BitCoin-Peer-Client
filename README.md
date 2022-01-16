# BitCoin-Peer-Client
Connects to an active BitCoin Peer, and locates a predetermined block number (height) by downloading block headers. Once required block height is required, the program will display information regarding the specific block such as block hash, merkle root hash, and transaction details.

Log.txt contains output example of a run.

## Usage
1. Clone onto local machine
```
  git clone https://github.com/henryxsong/BitCoin-Peer-Client.git
```

2. Navigate to local repository directory

3. Run the program
```
  python3 lab5.py
```

4. (Optional) Edit global variables to change block lookup number in lab5.py
```
  # change FIND_THIS_BLOCK to the block height you want to find
  # currently locates block #2021. 
  # per updated instructions in Teams, an arbitrary block height over 1000 is used :) 
  # set FIND_THIS_BLOCK = MY_SUID % 700000 to lookup originally specified block height
  FIND_THIS_BLOCK = 712500#2021 # MY_SUID % 700000 
```

5. (Optional) Edit BitCoin peer address in lab5.py
```
  # Hardcoded Bitcoin peer to connect to
  # Usually works consistently, but sometimes stalls and never finishes
  # Change this IP address if this peer is not functional
  # List of known working peers: 
  # - 67.210.228.203
  # - 81.171.22.143
  # - 185.64.116.15
  # - 217.64.47.138
  # - 51.68.36.57
  PEER_HOST = ('67.210.228.203', 8333)
```


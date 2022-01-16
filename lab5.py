"""
Name: Henry Song

CPSC-5520 | Lab #5 - Blockchain

Sometimes the message will be received incompletely, possible due to network issues.gi
Simply rerun the program to get the full message.

Best to run by redirecting output to a separate file: python3 lab5.py > log.txt
A lot of the output is long, but outputting to a log file will allow you to seee the full chain of events.
I had trouble running the program in CS2, but it worked fine on my local machine.
"""

import socket
import time
import hashlib
import urllib.parse
import ipaddress
import math
from time import strftime, gmtime

HDR_SZ = 24
BUF_SZ = 18027
MY_SUID = 4053312

# change FIND_THIS_BLOCK to the block height you want to find
# currently locates block #2021. 
# per updated instructions in Teams, an arbitrary block height over 1000 is used :) 
# set FIND_THIS_BLOCK = MY_SUID % 700000 to lookup originally specified block height
FIND_THIS_BLOCK = 712500#2021 # MY_SUID % 700000 

FILE_NAME = 'seeds_main.txt'
MAGIC = 'f9beb4d9'
MY_HOST = None

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


header_hashes = []

# not currently used, but left here for future reference
def read_file():
    """
    Read the contents of the file containing the list of seed nodes
    :return: list of IPv4 address, host tuples
    """
    storage = []
    counter = 0
    with open(FILE_NAME, 'r') as f:
        for line in f:
            storage.append(line[:50])
            counter += 1
            if counter == 100:     # only read 100 lines, the entire file is too large
                break
        f.close()


    results = []
    for i in storage:
        addr, host = parse_address(i)

        try:
            if ipaddress.IPv4Address(addr):
                results.append((addr, host))
        except ipaddress.AddressValueError as e:
            continue
    return results

# not currently used, but left here for future reference
def parse_address(addr):
    result = urllib.parse.urlsplit('//' + addr)
    return result.hostname, result.port

def connect_to_peer(host, port):
    """
    Connect to a peer at the given host and port
    :param host: the host to connect to
    :param port: the port to connect to
    :return: the socket
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    return s

def recvall(sock, n):
    """
    Receive n bytes from a socket
    Created to keep reading from socket, because i kept running into incomplete messages
    :param sock: the socket to read from
    :param n: the number of bytes to read
    :return: the bytes read
    """
    data = bytearray()
    while n > 0:
        packet = sock.recv(n)
        data.extend(packet)
        n -= len(packet)
    return data

def compactsize_t(n):
    if n < 252:
        return uint8_t(n)
    if n < 0xffff:
        return uint8_t(0xfd) + uint16_t(n)
    if n < 0xffffffff:
        return uint8_t(0xfe) + uint32_t(n)
    return uint8_t(0xff) + uint64_t(n)

def unmarshal_compactsize(b):
    key = b[0]
    if key == 0xff:
        return b[0:9], unmarshal_uint(b[1:9])
    if key == 0xfe:
        return b[0:5], unmarshal_uint(b[1:5])
    if key == 0xfd:
        return b[0:3], unmarshal_uint(b[1:3])
    return b[0:1], unmarshal_uint(b[0:1])

def bool_t(flag):
    return uint8_t(1 if flag else 0)

def ipv6_from_ipv4(ipv4_str):
    pchIPv4 = bytearray([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])
    return pchIPv4 + bytearray((int(x) for x in ipv4_str.split('.')))

def ipv6_to_ipv4(ipv6):
    return '.'.join([str(b) for b in ipv6[12:]])

def uint8_t(n):
    return int(n).to_bytes(1, byteorder='little', signed=False)

def uint16_t(n):
    return int(n).to_bytes(2, byteorder='little', signed=False)

def int32_t(n):
    return int(n).to_bytes(4, byteorder='little', signed=True)

def uint32_t(n):
    return int(n).to_bytes(4, byteorder='little', signed=False)

def int64_t(n):
    return int(n).to_bytes(8, byteorder='little', signed=True)

def uint64_t(n):
    return int(n).to_bytes(8, byteorder='little', signed=False)

def unmarshal_int(b):
    return int.from_bytes(b, byteorder='little', signed=True)

def unmarshal_uint(b):
    return int.from_bytes(b, byteorder='little', signed=False)

def print_message(msg, text=None):
    """
    Report the contents of the given bitcoin message
    :param msg: bitcoin message including header
    :return: message type
    """
    print('\n{}MESSAGE'.format('' if text is None else (text + ' ')))
    print('({}) {}'.format(len(msg), msg[:60].hex() + ('' if len(msg) < 60 else '...')))
    payload = msg[HDR_SZ:]
    command = print_header(msg[:HDR_SZ], checksum(payload))
    if command == 'version':
        print_version_msg(payload)
    # uncomment to see the contents of inv messages, which are large
    # elif command == 'inv':
    #     print_inv_msg(payload)
    elif command == 'getdata':
        print_getdata_msg(payload)
    elif command == 'block':
        print_block_msg(payload)
    elif command == 'headers':
        print_headers_msg(payload)

    return command

def print_version_msg(b):
    """
    Report the contents of the given bitcoin version message (sans the header)
    :param payload: version message contents
    """
    # pull out fields
    version, my_services, epoch_time, your_services = b[:4], b[4:12], b[12:20], b[20:28]
    rec_host, rec_port, my_services2, my_host, my_port = b[28:44], b[44:46], b[46:54], b[54:70], b[70:72]
    nonce = b[72:80]
    user_agent_size, uasz = unmarshal_compactsize(b[80:])
    i = 80 + len(user_agent_size)
    user_agent = b[i:i + uasz]
    i += uasz
    start_height, relay = b[i:i + 4], b[i + 4:i + 5]
    extra = b[i + 5:]

    # print report
    prefix = '  '
    print(prefix + 'VERSION')
    print(prefix + '-' * 56)
    prefix *= 2
    print('{}{:32} version {}'.format(prefix, version.hex(), unmarshal_int(version)))
    print('{}{:32} my services'.format(prefix, my_services.hex()))
    time_str = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime(unmarshal_int(epoch_time)))
    print('{}{:32} epoch time {}'.format(prefix, epoch_time.hex(), time_str))
    print('{}{:32} your services'.format(prefix, your_services.hex()))
    print('{}{:32} your host {}'.format(prefix, rec_host.hex(), ipv6_to_ipv4(rec_host)))
    print('{}{:32} your port {}'.format(prefix, rec_port.hex(), unmarshal_uint(rec_port)))
    print('{}{:32} my services (again)'.format(prefix, my_services2.hex()))
    print('{}{:32} my host {}'.format(prefix, my_host.hex(), ipv6_to_ipv4(my_host)))
    print('{}{:32} my port {}'.format(prefix, my_port.hex(), unmarshal_uint(my_port)))
    print('{}{:32} nonce'.format(prefix, nonce.hex()))
    print('{}{:32} user agent size {}'.format(prefix, user_agent_size.hex(), uasz))
    print('{}{:32} user agent \'{}\''.format(prefix, user_agent.hex(), str(user_agent, encoding='utf-8')))
    print('{}{:32} start height {}'.format(prefix, start_height.hex(), unmarshal_uint(start_height)))
    print('{}{:32} relay {}'.format(prefix, relay.hex(), bytes(relay) != b'\0'))
    if len(extra) > 0:
        print('{}{:32} EXTRA!!'.format(prefix, extra.hex()))
        print_message(extra, bytes.fromhex(extra[HDR_SZ:].hex()).decode('utf-8'))

def print_header(header, expected_cksum=None):
    """
    Report the contents of the given bitcoin message header
    :param header: bitcoin message header (bytes or bytearray)
    :param expected_cksum: the expected checksum for this version message, if known
    :return: message type
    """
    magic, command_hex, payload_size, cksum = header[:4], header[4:16], header[16:20], header[20:]
    command = str(bytearray([b for b in command_hex if b != 0]), encoding='utf-8')
    psz = unmarshal_uint(payload_size)
    if expected_cksum is None:
        verified = ''
    elif expected_cksum == cksum:
        verified = '(verified)'
    else:
        verified = '(WRONG!! ' + expected_cksum.hex() + ')'
    prefix = '  '
    print(prefix + 'HEADER')
    print(prefix + '-' * 56)
    prefix *= 2
    print('{}{:32} magic'.format(prefix, magic.hex()))
    print('{}{:32} command: {}'.format(prefix, command_hex.hex(), command))
    print('{}{:32} payload size: {}'.format(prefix, payload_size.hex(), psz))
    print('{}{:32} checksum {}'.format(prefix, cksum.hex(), verified))
    return command

def parse_inv_payload(payload):
    """
    Parse the contents of a bitcoin inv message
    Saves the results in the global variable header_hashes
    """
    byte_size, count = unmarshal_compactsize(payload)
    #header_hashes = []
    for i in range(len(byte_size), len(payload), 36):
        value = unmarshal_uint(payload[i:i+4])
        hash = str(payload[i+4:i+36].hex())
        
        header_hashes.append({'type':value, 'hash': hash})
    
    return byte_size, count
    
def print_inv_msg(b):
    """
    Print the contents of the given bitcoin inv message (sans the header)
    :param b: inv message contents
    """
    print_message(b[:HDR_SZ], 'received') # prints inv header (24 bytes)
    byte_size, count = unmarshal_compactsize(b)

    prefix = '  '
    print('\n' + prefix + 'INVENTORY PAYLOAD')
    print(prefix + '-' * 56)
    prefix *= 2
    print('{}{:32} count {}'.format(prefix, byte_size.hex(), count))
    counter = 0
    for entry in header_hashes:
        value = entry['type']
        if value == 1:
            value = 'MSG_TX'
        elif value == 2:
            value = 'MSG_BLOCK'
        elif value == 3:
            value = 'MSG_FILTERED_BLOCK'
        elif value == 4:
            value = 'MSG_CMPCT_BLOCK'
        print('{}{:5}.\tType: {}\t\tHash: {:40}'.format(prefix, counter, value, entry['hash']))
        counter += 1
    print('Number of hashes: ', len(header_hashes))

def print_getdata_msg(b):
    '''
    Prints getdata message
    '''
    count, value, hash = unmarshal_compactsize(b[:1]), unmarshal_uint(b[1:5]), b[5:]
    
    prefix = '  '
    print(prefix + 'GETDATA PAYLOAD')
    print(prefix + '-' * 56)
    prefix *= 2
    print('{}Count: \t{}\t'.format(prefix, count[1]))
    print('{}Value: \t{}\t'.format(prefix, value))
    print('{}Hash: \t{:32}'.format(prefix, hash.hex()))

def print_block_msg(b):
    '''
    Prints block message, response from sending getblocks message
    :param b: block message
    '''
    version, prev_block, merkle_root, timestamp, bits, nonce = b[:4], b[4:36], b[36:68], b[68:72], b[72:76], b[76:80]
    txn_count, count = unmarshal_compactsize(b[80:])
    i = 80 + len(txn_count)
    txns = b[i:]
    
    # calculates block height for display
    block_height = -1
    for i in range(len(header_hashes)):
        if header_hashes[i]['hash'] == prev_block.hex():
            block_height = i+1
            break

    # constructs link to blockchain.com explorer page
    block_link = 'https://www.blockchain.com/btc/block/' + str(block_height)

    prefix = '  '
    if block_height != -1:
        print(prefix + 'BLOCK #{} PAYLOAD | HASH = {}'.format(block_height, header_hashes[block_height]['hash']))
        print(prefix + 'Confirm data accuracy: {}'.format(block_link))

    print(prefix + 'NOTE: endian order for hashes (prev block & merkle root) different on website :)')
    print(prefix + '-' * 56)
    prefix *= 2
    print('{}Version: \t\t{}'.format(prefix, unmarshal_int(version)))
    print('{}Prev Block: \t{}'.format(prefix, prev_block.hex()))
    print('{}Merkle Root: \t{}'.format(prefix, merkle_root.hex()))
    time_str = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime(unmarshal_int(timestamp)))
    print('{}Timestamp: \t\t{}'.format(prefix, time_str))
    print('{}Bits: \t\t{}'.format(prefix, unmarshal_uint(bits)))#, bits.hex()))
    print('{}Nonce: \t\t{}'.format(prefix, unmarshal_uint(nonce)))#, nonce.hex()))
    print('{}Txn Count: \t\t{}'.format(prefix, count))#, txn_count.hex()))
    print('{}Txns: \t\t{:32}'.format(prefix, '(See Below)'))
    print_txn_payload(txns, count)

def print_txn_payload(b, count):
    '''
    Prints Txn payload
    :param b: txn payload
    :param count: number of txns in payload
    '''
    prefix = '    '
    print(prefix + 'TRANSACTION(S) PAYLOAD')
    print(prefix + '-' * 56)
    prefix *= 2
    step = 0
    for i in range(count):
        version = unmarshal_uint(b[step:step+4])
        step += 4
        
        flag = unmarshal_uint(b[step:2])
        if flag == 0:
            step += 0
        elif flag == 1:
            step += 2

        tx_in_count_bytes, tx_in_count = unmarshal_compactsize(b[step:])
        step += len(tx_in_count_bytes)

        tx_in, step_count = parse_tx_in(b[step:], tx_in_count)
        step += step_count

        tx_out_count_bytes, tx_out_count = unmarshal_compactsize(b[step:])
        step += len(tx_out_count_bytes)
        
        tx_out, step_count = parse_tx_out(b[step:], tx_out_count)
        step += step_count

        
        tx_witnesses, step_count = None, None #parse_tx_witnesses(b[step:])
        if flag == 1:
            tx_witnesses, step_count = parse_tx_witnesses(b[step:])
            step += step_count
        elif flag == 0:
            step += 0

        lock_time = unmarshal_uint(b[step:step + 4])
        step += 4

        #print(b[i+step:].hex())
        prefix1 = '      '
        print(prefix1 + 'TRANSACTION #{} out of {}'.format(i+1, count))
        print(prefix1 + '-' * 56)
        #prefix1 *= 2
        print('{}Version: \t{}'.format(prefix1+'  ', version))
        print('{}Flag: \t\t{}'.format(prefix1+'  ', flag))
        print('{}TxIn Count: \t{}'.format(prefix1+'  ', tx_in_count))
        print('{}TxIn: \t'.format(prefix1+'  '))

        for entry in tx_in:
            print('{}Previous_Output: \t{}'.format(prefix1+'    ', entry['prev_out_hash']))
            print('{}Script Length: \t{}'.format(prefix1+'    ', entry['script_length']))
            print('{}Sigscript: \t\t{}'.format(prefix1+'    ', entry['script']))
            print('{}Sequence: \t\t{}'.format(prefix1+'    ', entry['sequence']))

        print('{}TxOut Count: \t{}'.format(prefix1+'  ', tx_out_count))
        print('{}TxOut: \t\t'.format(prefix1+'  '))

        for entry in tx_out:
            print('{}Transaction Value: \t{} {}'.format(prefix1+'    ', entry['value'], 'BTC'))
            print('{}pk_script length: \t{}'.format(prefix1+'    ', entry['pk_script_length']))
            print('{}pk_script: \t\t{}'.format(prefix1+'    ', entry['pk_script']))

        if flag == 1:
            print('{}TxWitnesses: \t'.format(prefix1+'  '))

            for i in range(len(tx_witnesses)):
                print('{}Witness: \t{}'.format(prefix1+'    ', tx_witnesses[i]))

        print('{}Lock Time: \t{}'.format(prefix1+'  ', lock_time)) 

def parse_tx_in(b, tx_in_count):
    '''
    Parses TxIn structure
    :param b: bytes of the TxIn structure
    :param tx_in_count: number of TxIns
    :return: list of TxIn entries
    '''
    tx_in = []
    step = 0

    for i in range(tx_in_count):
        prev_out_hash = b[:36]
        step += 36

        bytes, script_length = unmarshal_compactsize(b[step:])
        step += len(bytes)

        script = b[step:step + script_length]
        step += len(script)

        sequence = unmarshal_uint(b[step:step + 4])
        step += 4

        tx_in.append({'prev_out_hash': prev_out_hash.hex(),
                      'script_length': script_length,
                      'script': script.hex(),
                      'sequence': sequence})
    return tx_in, step

def parse_tx_out(b, tx_out_count):
    '''
    Parses TxOut structure
    :param b: bytes of the tx_out structure
    :param tx_out_count: number of tx_outs
    :return: list of tx_outs
    '''
    tx_out = []
    step = 0

    for i in range(tx_out_count):
        # value is given in Satoshis, which is a subunit of BTC
        # so we need to multiply the conversion rate to find value in BTC
        # 1 Satoshi = 0.00000001 BTC
        value = unmarshal_int(b[step:step + 8]) * 0.00000001
        step += 8

        pks_bytes, pk_script_length = unmarshal_compactsize(b[step:])
        step += len(pks_bytes)

        pk_script = b[step:step + pk_script_length]
        step += len(pk_script)

        tx_out.append({'value': value, 
                       'pk_script_length': pk_script_length, 
                       'pk_script': pk_script.hex()})

    return tx_out, step

def parse_tx_witnesses(b):
    witnesses = []
    step = 0

    count_bytes, count = unmarshal_compactsize(b[step:])
    step += len(count_bytes)

    for i in range(count):
        witness_bytes, witness_length = unmarshal_compactsize(b[step:])
        step += len(witness_bytes)

        witness_data = b[step:step + witness_length]
        step += witness_length

        witnesses.append(witness_data.hex())
    return witnesses, step

# Used in response to 'getheaders' message
# since 'getheaders' is not used, this function is not used
def print_headers_msg(b):
    '''
    Prints headers message, response to sending 'getheaders' message
    '''
    size, count = unmarshal_compactsize(b)
    headers = b[len(size):]
    #print(count, ' ', len(headers))

    prefix = '  '
    print(prefix + 'HEADERS PAYLOAD')
    print(prefix + '-' * 56)
    print(prefix + 'Count: \t{}'.format(count))
    prefix *= 2

    counter = 1
    for i in range(0, len(headers), 81):
        # if headers[i:i+4].hex() == 'f9beb4d9':
        #     headers = headers[i+HDR_SZ:]
        version = headers[i:i+4]
        prev_block = headers[i+4:i+36]
        merkle_root = headers[i+36:i+68]
        timestamp = headers[i+68:i+72]
        bits = headers[i+72:i+76]
        nonce = headers[i+76:i+80]

        # print('{}Version: \t\t\t{}'.format(prefix, unmarshal_int(version)))#, version.hex()))
        print('{}{:5}. Prev Block: \t{}'.format(prefix, counter, prev_block.hex()))
        # print('{}Merkle Root: \t{}'.format(prefix, merkle_root.hex()))
        # time_str = strftime("%a, %d %b %Y %H:%M:%S GMT", gmtime(unmarshal_uint(timestamp)))
        # print('{}Timestamp: \t\t{}'.format(prefix, time_str))
        # print('{}Bits: \t\t\t\t{}'.format(prefix, unmarshal_uint(bits)))#, bits.hex()))
        # print('{}Nonce: \t\t\t\t{}'.format(prefix, unmarshal_uint(nonce)))#, nonce.hex()))
        # print()
        header_hashes.append(prev_block.hex())
        counter += 1
    
def checksum(payload):
    '''
    Returns the last 4 bytes of the SHA256(SHA256) hash of the payload
    '''
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

def create_message(cmd, arg1=None):
    '''
    Creates a message based on the given command
    '''
    if cmd == 'version':
        return create_version_message()
    elif cmd == 'verack':
        return create_header_message(cmd)
    elif cmd == 'getblocks':
        return create_getblocks_message()
    elif cmd == 'getdata':
        return create_getdata_message(arg1)
    # elif cmd == 'getheaders': # <-- getheaders is not used
    #     return create_getheaders_message(block_hash)
    elif cmd == 'sendheaders':
        return create_header_message(cmd)

def create_header_message(cmd: str, payload=b''):
    '''
    Generates standard header message
    '''
    magic = bytes.fromhex(MAGIC) #magic bytes (4 bytes)
    command = cmd.encode('utf-8') + (12 - len(cmd)) * b'\00' # command (12 bytes)
    payload_size = uint32_t(len(payload)) # payload size (4 bytes)
    chksum = checksum(payload) # checksum of payload (4 bytes)
    return magic + command + payload_size + chksum

def create_version_message():
    '''
    Generates version message
    '''
    version = int32_t(70015) # version (4 bytes)
    my_services = uint64_t(0) # services (8 bytes)
    epoch_time = int64_t(time.time()) # timestamp (8 bytes)
    your_services = uint64_t(0) # addr_recv services (8 bytes)
    part1 = version+my_services+epoch_time+your_services
    
    rec_host = ipv6_from_ipv4(PEER_HOST[0]) # addr_recv ip (16 bytes)
    rec_port = uint16_t(PEER_HOST[1]) # addr_recv port (2 bytes)
    my_services2 = uint64_t(0) # addr_trans services (8 bytes)
    my_host = ipv6_from_ipv4(MY_HOST[0]) # addr_trans ip (16 bytes)
    my_port = uint16_t(MY_HOST[1]) # addr_trans port (2 bytes)
    nonce = uint64_t(0) # nonce (8 bytes)
    part2 = rec_host+rec_port+my_services2+my_host+my_port+nonce

    user_agent_size = compactsize_t(0) # user_agent bytes (varies)
    start_height = int32_t(0) # start_height (4 bytes)
    relay = bool_t(False) # relay (1 byte)
    part3 = user_agent_size + start_height + relay

    payload = part1 + part2 + part3
    header = create_header_message('version', payload)
    return header + payload

def create_getblocks_message():
    '''
    Generates getblocks message
    '''
    version = uint32_t(70015) # version (4 bytes)

    block_hash = b''
    counter = 0
    if len(header_hashes) == 1:
        # initial run, only the genesis block (block #0) hash is known
        block_hash = bytes.fromhex(header_hashes[0]['hash'])#.encode('utf-8')
        counter = 1
    else:
        # more block hashes are known, uses the latest 20 block hashes
        # to create a getblocks message
        # per Blocks-First section of https://developer.bitcoin.org/devguide/p2p_network.html
        for i in range(len(header_hashes), len(header_hashes)-20, -1):
            block_hash += bytes.fromhex(header_hashes[i-1]['hash'])#.encode('utf-8')
            counter += 1

    count = compactsize_t(counter) # count (4 bytes)
    stop_hash = b'\00' * 32 # block_hash (32 bytes)

    payload = version + count + block_hash + stop_hash
    header = create_header_message('getblocks', payload)
    return header + payload

# NOT USED, but kept for testing purposes.
def create_getheaders_message(last_block_hash):
    '''
    Generates getheaders message, can return first 2000 block header hashes, but not the next 2000
    '''
    version = uint32_t(70015) # version (4 bytes)
    count = compactsize_t(1) # count (4 bytes)

    block_hash = b'\00' * 32#last_block_hash.encode('utf-8') # block_hash (32 bytes)
    stop_hash = b'\00' * 32 # block_hash (32 bytes)

    payload = version + count + block_hash + stop_hash

    header = create_header_message('getheaders', payload)
    return header + payload

def create_getdata_message(entry):
    '''
    Generates getdata message
    '''
    count = compactsize_t(1) # count (4 bytes)
    value = uint32_t(entry['type']) # value (4 bytes)
    hash = bytearray.fromhex(entry['hash']) # hash (32 bytes)

    payload = count + value + hash
    header = create_header_message('getdata', payload)
    return header + payload


if __name__ == '__main__':
    # connect to the peer
    sock = None
    try:
        print('Connecting to peer: {}:{}'.format(PEER_HOST[0], PEER_HOST[1])) # hardcoded peer
        sock = connect_to_peer(PEER_HOST[0], PEER_HOST[1])
        MY_HOST = sock.getsockname()
        print('SUCCESS: Socket connection established to peer {}:{}'.format(PEER_HOST[0], PEER_HOST[1]))
    except socket.error as e:
        print('FAILED: {} to {}:{} failed'.format( e, PEER_HOST[0], PEER_HOST[1]))
        exit(1)
    except Exception as e:
        print(e)
    
    print('Sending message to peer {}:{}'.format(PEER_HOST[0], PEER_HOST[1]))

    # version message
    version_msg = create_message('version')
    print_message(version_msg, 'sending')
    sock.sendall(version_msg)
    version_response = sock.recv(BUF_SZ)
    if len(version_response) < 126:
        print('Received Version msg incomplete, please re-run')
        exit(1)
    print_message(version_response[:126], 'received')
    if len(version_response) > 126:
        print_message(version_response[126:], 'received') # <-- verack message automatically sent by peer

    # verack message
    while True:
        verack_msg = create_message('verack')
        print_message(verack_msg, 'sending')
        sock.sendall(verack_msg)
        verack_response = sock.recv(209)
        if len(verack_response) == 209:
            print_message(verack_response[:24], 'received') # <-- received sendheaders
            print_message(verack_response[24:57], 'received') # <-- received sendcmpct
            print_message(verack_response[57:90], 'received') # <-- received sendcmpct
            print_message(verack_response[90:122], 'received') # <-- received ping
            print_message(verack_response[122:177], 'received') # <-- received addr
            print_message(verack_response[177:], 'received') # <-- received feefilter
            break
        else:
            print('Received VerAck msg incomplete, please re-run...')
            exit(1)
    
    # adds genesis block to header_hashes, as it is the first block (block 0)
    # per lab instructions, this is the only block hash that I "know" about
    header_hashes.append({'type': 2, 'hash':'6FE28C0AB6F1B372C1A6A246AE63F74F931E8365E15A089C68D6190000000000'})
    
    print()
    print('BUILDING LOCAL BLOCKCHAIN...')
    print('Please wait, this part might take a while')
    print('Grab a coffee while you wait :)')
    print()

    # getblocks message
    number_of_iterations = int(math.ceil(FIND_THIS_BLOCK / 500))
    for i in range(number_of_iterations):
        getblocks_msg = create_message('getblocks')
        
        sock.sendall(getblocks_msg)
        inv_response = recvall(sock, 18027) # <-- statically set to 18027 bytes, len of inv message
        temp, temp = parse_inv_payload(inv_response[HDR_SZ:]) # temp, temp never used
        if number_of_iterations > 5 and i % 50 == 0:
            print_message(getblocks_msg, 'sending')
            print_message(inv_response, 'received') # <-- received INV message, response to sending getblocks message
        elif number_of_iterations <= 5:
            print_message(getblocks_msg, 'sending')
            print_message(inv_response, 'received')

        print('Local blockchain height (# of hashes found): ', len(header_hashes))
    
    print()
    print('...REQUIRED LOCAL BLOCKCHAIN HEIGHT REACHED')

    # getdata message
    getdata_msg = create_message('getdata', header_hashes[FIND_THIS_BLOCK])
    print_message(getdata_msg, 'sending')
    sock.sendall(getdata_msg)
    block_header = sock.recv(HDR_SZ)
    block_payload = recvall(sock, unmarshal_uint(block_header[16:20]))
    print_message(block_header+block_payload, 'received') # <-- received block message, response to sending getdata message



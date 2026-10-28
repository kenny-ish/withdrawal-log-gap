#!/usr/bin/env python3
"""Reconcile OP Stack MessagePassed logs with the withdrawal nonce and mapping."""
import argparse
import json
import re
import sys
import urllib.request

CONTRACT = "0x4200000000000000000000000000000000000016"
MASK = (1 << 64) - 1
SEQUENCE_MASK = (1 << 240) - 1
ROT = ((0, 36, 3, 41, 18), (1, 44, 10, 45, 2),
       (62, 6, 43, 15, 61), (28, 55, 25, 21, 56), (27, 20, 39, 8, 14))
RC = (0x1, 0x8082, 0x800000000000808a, 0x8000000080008000,
      0x808b, 0x80000001, 0x8000000080008081, 0x8000000000008009,
      0x8a, 0x88, 0x80008009, 0x8000000a, 0x8000808b,
      0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
      0x8000000000008002, 0x8000000000000080, 0x800a,
      0x800000008000000a, 0x8000000080008081, 0x8000000000008080,
      0x80000001, 0x8000000080008008)


def keccak256(data):
    """Ethereum Keccak-256, including its original 0x01 domain padding."""
    def rotate(n, r):
        return ((n << r) | (n >> ((64 - r) % 64))) & MASK

    padded = bytearray(data)
    padded.extend(bytes(136 - len(data) % 136))
    padded[len(data)] = 1
    padded[-1] |= 128
    state = [0] * 25
    for offset in range(0, len(padded), 136):
        for i in range(17):
            state[i] ^= int.from_bytes(padded[offset + i*8:offset + i*8 + 8], 'little')
        for rc in RC:
            c = [state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20]
                 for x in range(5)]
            d = [c[(x-1) % 5] ^ rotate(c[(x+1) % 5], 1) for x in range(5)]
            b = [0] * 25
            for y in range(5):
                for x in range(5):
                    b[y + 5*((2*x + 3*y) % 5)] = rotate(state[x+5*y] ^ d[x], ROT[x][y])
            for y in range(5):
                for x in range(5):
                    state[x+5*y] = b[x+5*y] ^ (~b[(x+1) % 5+5*y] & b[(x+2) % 5+5*y])
            state[0] ^= rc
    return b''.join(n.to_bytes(8, 'little') for n in state)[:32]


def signature(text):
    return '0x' + keccak256(text.encode('ascii')).hex()


TOPIC = signature('MessagePassed(uint256,address,address,uint256,uint256,bytes,bytes32)')
NONCE_CALL = signature('messageNonce()')[:10]
SENT_CALL = signature('sentMessages(bytes32)')[:10]


def raw(value, size=None):
    if not isinstance(value, str) or re.fullmatch(r'0x(?:[0-9a-fA-F]{2})*', value) is None:
        raise ValueError('invalid hex data')
    result = bytes.fromhex(value[2:])
    if size is not None and len(result) != size:
        raise ValueError('unexpected hex data length')
    return result


def quantity(value):
    if not isinstance(value, str) or re.fullmatch(r'0x(?:0|[1-9a-fA-F][0-9a-fA-F]*)', value) is None:
        raise ValueError('invalid RPC quantity')
    return int(value, 16)


def word(value):
    return value.to_bytes(32, 'big')


def uint(value):
    return int.from_bytes(raw(value, 32), 'big')


class JsonRpc:
    def __init__(self, url, timeout=30):
        if not url.startswith(('http://', 'https://')) or timeout <= 0:
            raise ValueError('HTTP(S) RPC URL and positive timeout required')
        self.url, self.timeout, self.counter = url, timeout, 0

    def request(self, method, params):
        self.counter += 1
        request = urllib.request.Request(
            self.url, json.dumps({'jsonrpc': '2.0', 'id': self.counter,
                                 'method': method, 'params': params}).encode(),
            {'Content-Type': 'application/json', 'User-Agent': 'withdrawal-log-gap/1.0'})
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            result = json.load(response)
        if (not isinstance(result, dict) or result.get('jsonrpc') != '2.0'
                or result.get('id') != self.counter or 'error' in result
                or 'result' not in result):
            raise ValueError('invalid or failed RPC response for ' + method)
        return result['result']


def decode_log(log):
    topics = log['topics']
    if (log['address'].lower() != CONTRACT or log.get('removed') is not False
            or len(topics) != 4 or topics[0].lower() != TOPIC):
        raise ValueError('unexpected, removed, or malformed withdrawal log')
    nonce, sender, target = (raw(t, 32) for t in topics[1:])
    if any(sender[:12]) or any(target[:12]):
        raise ValueError('noncanonical address topic')
    data = raw(log['data'])
    if len(data) < 160 or int.from_bytes(data[64:96], 'big') != 128:
        raise ValueError('noncanonical event ABI head')
    size = int.from_bytes(data[128:160], 'big')
    if len(data) != 160 + ((size + 31) // 32) * 32 or any(data[160+size:]):
        raise ValueError('invalid event bytes length or padding')
    encoded = nonce + sender + target + data[:64] + word(192) + data[128:]
    calculated = keccak256(encoded)
    if calculated != data[96:128]:
        raise ValueError('withdrawal hash does not match event fields')
    raw(log['blockHash'], 32)
    raw(log['transactionHash'], 32)
    return {'nonce': int.from_bytes(nonce, 'big'), 'hash': '0x' + calculated.hex(),
            'block': quantity(log['blockNumber']), 'block_hash': log['blockHash'].lower(),
            'transaction_hash': log['transactionHash'].lower(),
            'tx_index': quantity(log['transactionIndex']), 'log_index': quantity(log['logIndex'])}


def missing_ranges(first, stop, sequences):
    """Find inclusive gaps without allocating an array for the nonce interval."""
    if first < 0 or stop < first:
        raise ValueError('invalid nonce interval')
    cursor, gaps = first, []
    for value in sequences:
        if value < cursor or value >= stop:
            raise ValueError('duplicate, reversed, or out-of-range nonce')
        if value > cursor:
            gaps.append([cursor, value-1])
        cursor = value + 1
    if cursor < stop:
        gaps.append([cursor, stop-1])
    return gaps


def block_hash(rpc, height):
    block = rpc.request('eth_getBlockByNumber', [hex(height), False])
    if not isinstance(block, dict) or quantity(block['number']) != height:
        raise ValueError('requested block is unavailable')
    raw(block['hash'], 32)
    return block['hash'].lower()


def read_state(rpc, calldata, height):
    return uint(rpc.request('eth_call', [{'to': CONTRACT, 'data': calldata}, hex(height)]))


def audit(rpc, start, end, chunk=2000, chain_id=10):
    if start < 1 or end < start or chunk < 1 or chain_id < 1:
        raise ValueError('require 1 <= start <= end, positive chunk and chain ID')
    if quantity(rpc.request('eth_chainId', [])) != chain_id:
        raise ValueError('unexpected chain ID')
    anchors = {n: block_hash(rpc, n) for n in (start-1, end)}
    before = read_state(rpc, NONCE_CALL, start-1)
    after = read_state(rpc, NONCE_CALL, end)
    if before >> 240 != 1 or after >> 240 != 1:
        raise ValueError('only nonce version 1 is supported; split upgrade windows')
    first, stop = before & SEQUENCE_MASK, after & SEQUENCE_MASK
    events, seen = [], set()
    for lo in range(start, end+1, chunk):
        hi = min(end, lo+chunk-1)
        logs = rpc.request('eth_getLogs', [{'address': CONTRACT, 'topics': [TOPIC],
                           'fromBlock': hex(lo), 'toBlock': hex(hi)}])
        if not isinstance(logs, list):
            raise ValueError('eth_getLogs must return a list')
        for log in logs:
            event = decode_log(log)
            if not lo <= event['block'] <= hi or event['nonce'] >> 240 != 1:
                raise ValueError('log outside requested window or nonce version')
            identity = (event['block'], event['log_index'])
            if identity in seen:
                raise ValueError('duplicate log identity')
            seen.add(identity)
            events.append(event)
    events.sort(key=lambda e: (e['block'], e['tx_index'], e['log_index']))
    gaps = missing_ranges(first, stop, [e['nonce'] & SEQUENCE_MASK for e in events])
    headers = dict(anchors)
    unset = []
    for event in events:
        height = event['block']
        if height not in headers:
            headers[height] = block_hash(rpc, height)
        if headers[height] != event['block_hash']:
            raise ValueError('event is not in the canonical block')
        sent = read_state(rpc, SENT_CALL + event['hash'][2:], end)
        if sent not in (0, 1):
            raise ValueError('noncanonical sentMessages bool')
        if not sent:
            unset.append(event['hash'])
    for height, expected in anchors.items():
        if block_hash(rpc, height) != expected:
            raise ValueError('chain changed during audit; rerun on finalized blocks')
    return {'chain_id': chain_id, 'from_block': start, 'to_block': end,
            'end_hash': anchors[end], 'next_nonce_before': first,
            'next_nonce_after': stop, 'expected_events': stop-first,
            'observed_events': len(events), 'missing_ranges': gaps,
            'unset_hashes': unset, 'status': 'mismatch' if gaps or unset else 'ok'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rpc-url', required=True)
    parser.add_argument('--from-block', type=int, required=True)
    parser.add_argument('--to-block', type=int, required=True)
    parser.add_argument('--chain-id', type=int, default=10)
    parser.add_argument('--chunk', type=int, default=2000)
    parser.add_argument('--timeout', type=float, default=30)
    args = parser.parse_args(argv)
    try:
        report = audit(JsonRpc(args.rpc_url, args.timeout), args.from_block,
                       args.to_block, args.chunk, args.chain_id)
    except (ValueError, KeyError, TypeError, OSError) as exc:
        print('audit unavailable: ' + str(exc), file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report['status'] == 'ok' else 1


if __name__ == '__main__':
    raise SystemExit(main())

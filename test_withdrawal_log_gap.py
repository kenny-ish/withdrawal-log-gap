import contextlib
import copy
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import withdrawal_log_gap as m

FIXTURE = json.loads(Path(__file__).with_name('fixture.json').read_text())


def _word(value):
    return int(value).to_bytes(32, 'big')


def _address_word(address):
    return bytes.fromhex('00' * 12 + address[2:])


def make_log(case):
    event = case['event']
    payload = bytes.fromhex(event['test_payload'][2:])
    data = (
        _word(event['value'])
        + _word(event['gas_limit'])
        + _word(128)
        + bytes.fromhex(event['test_emitted_hash'][2:])
        + _word(len(payload))
        + payload
        + bytes((-len(payload)) % 32)
    )
    topics = [
        m.TOPIC,
        '0x' + _word(int(event['nonce'], 16)).hex(),
        '0x' + _address_word(event['sender']).hex(),
        '0x' + _address_word(event['target']).hex(),
    ]
    return {
        'address': m.CONTRACT,
        'blockHash': event['block_hash'],
        'blockNumber': hex(event['block']),
        'data': '0x' + data.hex(),
        'logIndex': hex(event['log_index']),
        'removed': False,
        'topics': topics,
        'transactionHash': event['transaction_hash'],
        'transactionIndex': hex(event['transaction_index']),
    }


class FakeRpc:
    def __init__(self, case_index=0):
        self.case = copy.deepcopy(FIXTURE['cases'][case_index])
        self.logs = [make_log(self.case)]
        self.calls = []
        self.reorg = False

    def request(self, method, params):
        self.calls.append((method, params))
        if method == 'eth_chainId':
            return FIXTURE['chain_id']
        if method == 'eth_getBlockByNumber':
            n = str(int(params[0], 16))
            block = copy.deepcopy(self.case['blocks'][n])
            count = self.calls.count((method, params))
            if self.reorg and count > 1:
                block['hash'] = '0x' + '11' * 32
            return block
        if method == 'eth_getLogs':
            lo, hi = int(params[0]['fromBlock'], 16), int(params[0]['toBlock'], 16)
            return [copy.deepcopy(log) for log in self.logs
                    if lo <= int(log['blockNumber'], 16) <= hi]
        if method == 'eth_call':
            call, tag = params
            if call['data'] == m.NONCE_CALL:
                return self.case['before'] if int(tag, 16) < self.case['start'] else self.case['after']
            if call['data'].startswith(m.SENT_CALL):
                return '0x' + '00' * 31 + '01'
        raise AssertionError((method, params))


class WithdrawalTests(unittest.TestCase):
    def setUp(self):
        self.rpc = FakeRpc(0)
        self.start, self.end = self.rpc.case['start'], self.rpc.case['end']
        self.guard = patch('urllib.request.urlopen', side_effect=AssertionError('network forbidden'))
        self.guard.start()
        self.addCleanup(self.guard.stop)

    def run_audit(self, **kwargs):
        return m.audit(self.rpc, self.start, self.end, **kwargs)

    def test_real_event_topic(self):
        self.assertEqual(m.TOPIC, FIXTURE['topic'])

    def test_both_fixed_live_case_headers_and_hashes(self):
        for index, case in enumerate(FIXTURE['cases']):
            with self.subTest(case=case['name']):
                event = m.decode_log(FakeRpc(index).logs[0])
                self.assertEqual(event['hash'], case['event']['test_emitted_hash'])
                self.assertEqual(event['block_hash'], case['event']['block_hash'])
                self.assertEqual(event['transaction_hash'], case['event']['transaction_hash'])
                self.assertEqual(case['event']['block_hash'], case['blocks'][str(case['event']['block'])]['hash'])

    def test_keccak_vectors(self):
        self.assertEqual('0x' + m.keccak256(b'').hex(), FIXTURE['keccak_vectors']['0'])
        self.assertEqual('0x' + m.keccak256(b'\xc0').hex(), FIXTURE['keccak_vectors']['c0'])
        self.assertEqual(len(m.ROT), 5)
        self.assertEqual(sum(len(row) for row in m.ROT), 25)
        self.assertEqual(len(m.RC), 24)

    def test_block_uncle_hash_for_both_live_cases(self):
        for case in FIXTURE['cases']:
            expected = case['blocks'][str(case['end'])]['sha3Uncles']
            self.assertEqual('0x' + m.keccak256(b'\xc0').hex(), expected)

    def test_both_live_cases_reconcile(self):
        for index, case in enumerate(FIXTURE['cases']):
            report = m.audit(FakeRpc(index), case['start'], case['end'])
            with self.subTest(case=case['name']):
                self.assertEqual(report['status'], 'ok')
                self.assertEqual(report['observed_events'], 1)
                self.assertEqual(report['expected_events'], 1)
                self.assertEqual(report['next_nonce_before'], int(case['before'], 16) & m.SEQUENCE_MASK)
                self.assertEqual(report['next_nonce_after'], int(case['after'], 16) & m.SEQUENCE_MASK)

    def test_entire_log_response_missing(self):
        self.rpc.logs = []
        report = self.run_audit()
        first = report['next_nonce_before']
        self.assertEqual(report['status'], 'mismatch')
        self.assertEqual(report['missing_ranges'], [[first, first]])

    def test_gap_boundaries_and_middle(self):
        self.assertEqual(m.missing_ranges(10, 18, [11, 12, 16]), [[10, 10], [13, 15], [17, 17]])

    def test_empty_interval(self):
        self.assertEqual(m.missing_ranges(10, 10, []), [])

    def test_huge_gap_without_materializing_nonces(self):
        self.assertEqual(m.missing_ranges(0, 1 << 239, []), [[0, (1 << 239) - 1]])

    def test_invalid_nonce_intervals(self):
        for values in ([10, 10], [12, 11], [9], [18]):
            with self.subTest(values=values), self.assertRaises(ValueError):
                m.missing_ranges(10, 18, values)
        with self.assertRaises(ValueError):
            m.missing_ranges(18, 10, [])

    def test_duplicate_log_rejected(self):
        self.rpc.logs *= 2
        with self.assertRaisesRegex(ValueError, 'duplicate log'):
            self.run_audit()

    def test_removed_log_rejected(self):
        self.rpc.logs[0]['removed'] = True
        with self.assertRaises(ValueError):
            self.run_audit()

    def test_wrong_contract_rejected(self):
        self.rpc.logs[0]['address'] = '0x' + '00' * 20
        with self.assertRaises(ValueError):
            self.run_audit()

    def test_malformed_abi_and_corrupted_hash(self):
        source = self.rpc.logs[0]
        payload = m.raw(source['data'])
        bad = [payload[:120], payload[:64] + _word(64) + payload[96:],
               payload[:96] + bytes(32) + payload[128:], payload + bytes(32),
               payload[:-1] + b'\x01']
        for data in bad:
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                m.decode_log(dict(source, data='0x' + data.hex()))

    def test_hash_not_in_mapping(self):
        self.rpc.request = lambda method, params: (
            '0x' + '00' * 32 if method == 'eth_call' and params[0]['data'].startswith(m.SENT_CALL)
            else FakeRpc.request(self.rpc, method, params))
        report = self.run_audit()
        self.assertEqual(report['status'], 'mismatch')
        self.assertEqual(len(report['unset_hashes']), 1)

    def test_noncanonical_bool(self):
        self.rpc.request = lambda method, params: (
            '0x' + _word(2).hex() if method == 'eth_call' and params[0]['data'].startswith(m.SENT_CALL)
            else FakeRpc.request(self.rpc, method, params))
        with self.assertRaises(ValueError):
            self.run_audit()

    def test_version_upgrade_rejected(self):
        self.rpc.case['after'] = '0x' + _word(2 << 240).hex()
        with self.assertRaisesRegex(ValueError, 'version'):
            self.run_audit()

    def test_reorg_rejected(self):
        self.rpc.reorg = True
        with self.assertRaisesRegex(ValueError, 'chain changed'):
            self.run_audit()

    def test_log_block_hash_rejected(self):
        self.rpc.logs[0]['blockHash'] = '0x' + '22' * 32
        with self.assertRaisesRegex(ValueError, 'canonical block'):
            self.run_audit()

    def test_chain_id_and_input_validation(self):
        with self.assertRaises(ValueError):
            self.run_audit(chain_id=1)
        for start, end, chunk in [(0, 1, 1), (2, 1, 1), (1, 2, 0)]:
            with self.assertRaises(ValueError):
                m.audit(self.rpc, start, end, chunk)

    def test_chunk_boundaries(self):
        self.assertEqual(self.run_audit(chunk=1)['status'], 'ok')
        calls = [params[0] for method, params in self.rpc.calls if method == 'eth_getLogs']
        self.assertEqual(len(calls), 3)
        self.assertEqual([int(params['fromBlock'], 16) for params in calls], list(range(self.start, self.end + 1)))

    def test_cli_exit_codes(self):
        args = ['--rpc-url', 'https://unused.invalid', '--from-block', str(self.start),
                '--to-block', str(self.end)]
        with patch.object(m, 'JsonRpc', return_value=self.rpc), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(m.main(args), 0)
            self.rpc.logs = []
            self.assertEqual(m.main(args), 1)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(m.main(args + ['--chain-id', '1']), 2)

    def test_rpc_transport_errors_and_user_agent(self):
        for envelope, valid in [({'jsonrpc': '2.0', 'id': 1, 'result': '0xa'}, True),
                                ({'jsonrpc': '2.0', 'id': 2, 'result': '0xa'}, False),
                                ({'jsonrpc': '2.0', 'id': 1, 'error': {'code': -32000}}, False)]:
            with patch('urllib.request.urlopen') as open_url:
                open_url.return_value.__enter__.return_value = io.BytesIO(json.dumps(envelope).encode())
                rpc = m.JsonRpc('https://unused.invalid')
                if valid:
                    self.assertEqual(rpc.request('eth_chainId', []), '0xa')
                    self.assertEqual(dict(open_url.call_args.args[0].header_items())['User-agent'], 'withdrawal-log-gap/1.0')
                else:
                    with self.assertRaises(ValueError):
                        rpc.request('eth_chainId', [])


if __name__ == '__main__':
    unittest.main()

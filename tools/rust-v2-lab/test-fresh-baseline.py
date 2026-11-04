#!/usr/bin/env python3
"""Synthetic, offline netlink decoding regressions. Never contacts a guest."""
import copy
import importlib.util
import json
import pathlib
import struct
import unittest
from unittest.mock import patch

if not __debug__:
    raise RuntimeError('optimized_python_refused')

PATH = pathlib.Path(__file__).with_name('fresh-baseline.py')
SPEC = importlib.util.spec_from_file_location('fresh_baseline', PATH)
BASELINE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BASELINE)


def message(request, family, metric_or_priority):
    body = struct.pack('=BBBBBBBBI', family, 0, 0, 0, 254,
                       3 if request == 26 else 0, 0, 1, 0)
    body += struct.pack('=HHI', 8, 6, metric_or_priority)
    return (struct.pack('=IHHII', 16 + len(body), request - 2, 0, 1, 0) + body).hex()


def saved_dump():
    return dict(namespace=[4, 99], dumps={
        '18/0': [], '22/0': [],
        '26/2': [message(26, 2, 10)], '26/10': [message(26, 10, 20)],
        '34/2': [message(34, 2, 30)], '34/10': [message(34, 10, 40)],
    })


class FamilyOrder(unittest.TestCase):
    def setUp(self):
        # Any accidental subprocess/guest action makes these pure tests fail.
        guard = patch.object(BASELINE.subprocess, 'run', side_effect=AssertionError('offline only'))
        guard.start()
        self.addCleanup(guard.stop)
        self.expected = dict(namespace=[4, 99], links=[], addresses=[], routes=[
            dict(nexthop_id=None, preference=0, destination=destination, prefix=0,
                 table=254, output=0, source=None, gateway=None, kind=1, scope=0,
                 protocol=3, metric=metric, flags=0)
            for destination, metric in [('0.0.0.0', 10), ('::', 20)]
        ], rules=[
            dict(ipv6=ipv6, priority=priority, table=254, action=1, flags=0,
                 fwmark=None, fwmask=None, suppress_prefixlen=None,
                 suppress_ifgroup=None, goto=None, realm=None, protocol=None)
            for ipv6, priority in [(False, 30), (True, 40)]
        ])

    def test_both_dump_insertion_orders_decode_ipv4_before_ipv6(self):
        data = saved_dump()
        for reverse in (False, True):
            with self.subTest(reverse=reverse):
                ordered = dict(data, dumps=dict(sorted(data['dumps'].items(), reverse=reverse)))
                self.assertEqual(BASELINE.decode(ordered), self.expected)

    def test_sort_keys_round_trip_keeps_explicit_family_order(self):
        data = saved_dump()
        for reverse in (False, True):
            with self.subTest(reverse=reverse):
                ordered = dict(data, dumps=dict(reversed(list(data['dumps'].items()))) if reverse else data['dumps'])
                self.assertEqual(BASELINE.decode(json.loads(json.dumps(ordered, sort_keys=True))), self.expected)

    def test_within_family_record_order_and_multiplicity_are_preserved(self):
        data = saved_dump()
        data['dumps']['26/2'] += [message(26, 2, 11), message(26, 2, 10)]
        expected = copy.deepcopy(self.expected)
        extra = dict(expected['routes'][0], metric=11)
        expected['routes'][1:1] = [extra, expected['routes'][0].copy()]
        self.assertEqual(BASELINE.decode(data), expected)

    def test_missing_dump_groups_are_rejected(self):
        for group in saved_dump()['dumps']:
            with self.subTest(group=group):
                data = saved_dump()
                del data['dumps'][group]
                with self.assertRaises((AssertionError, KeyError)):
                    BASELINE.decode(data)

    def test_unexpected_dump_groups_are_rejected(self):
        data = saved_dump()
        data['dumps']['26/0'] = []
        with self.assertRaises(AssertionError):
            BASELINE.decode(data)


if __name__ == '__main__':
    unittest.main(verbosity=2)

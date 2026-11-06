#!/usr/bin/env python3
"""Offline typed validation of the frozen run-410 successful Bootstrap witness.

No guest actions, locks, claims or imported controller code. Only an explicitly
requested receipt is written, with O_EXCL/O_NOFOLLOW and mode 0600. This validates
recorded assertions and their consistency, never current native custody.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sys

if not __debug__:
    raise RuntimeError('optimized_python_refused')

ROOT = Path(__file__).resolve().parents[2]
CANDIDATE = Path('target/candidates/run410-da75562-20261104/candidate.json')
RESERVATION = Path('target/lab-state/run-410-reservation.json')
CLAIM = Path('target/lab-state/run-410-consumed.json')
SOURCE_COMMIT = 'da7556282d5fc828a9391a64ab47adab05a55510'
UNIT = r'vprouter-v2-owner@[a-f0-9]{64}[.]service'
# Three scopes x (ten field mutations + three missing-value mutations):
# crates/vprouter-launch/src/owned/preparation/bootstrap.rs:855-889.
CANONICAL_NEGATIVE_CHECKS = 3 * (10 + 3)
LIMITS = [
    'No real disposable Tailscale client, traffic capture or leak acceptance.',
    'No multi-exit runtime, isolation/fault matrix or direct-mode acceptance.',
    'No ARM runtime execution or platform qualification.',
    'No performance, CPU attribution, sleep/constructor samples or speedup proof.',
    'No migration, reboot/rollback, compatibility-deployment or soak acceptance.',
    'No current guest liveness, retained native custody or post-run live identity proof.',
    'No operational UP, placement, health READY, resource cleanup or requirement 8 completion.',
]

# The generated source contract is the sole type/enum/array authority.
CONTRACT_PATH = Path(__file__).with_name('witness-contract.json')
CONTRACT_BYTES = CONTRACT_PATH.read_bytes()
CONTRACT = json.loads(CONTRACT_BYTES)
CONTRACT_SHA256 = hashlib.sha256(CONTRACT_BYTES).hexdigest()
SCHEMAS = CONTRACT['schemas']
ENUMS = CONTRACT['enums']
INTEGER_RANGES = {**{f'u{bits}': (0, 2**bits-1) for bits in (8,16,32,64)},
                  **{f'i{bits}': (-2**(bits-1),2**(bits-1)-1) for bits in (8,16,32,64)},
                  'usize': (0,2**CONTRACT['target_pointer_width']-1),
                  'isize': (-2**(CONTRACT['target_pointer_width']-1),2**(CONTRACT['target_pointer_width']-1)-1)}


# Exact reviewed guard IDs. New or changed source guards have no default.
ENFORCED_GUARDS = {('allocation_contract',): ['0e406543e19425e92533',
                            '30cabd9ec1e0b8ec44b4',
                            '31b11fa6ae872ec5362a',
                            '51db98dd2e63652ebde0',
                            '77d29f56288f89eefb07',
                            '8572848dac54fd165709',
                            '8c1302f07cb8b6fe9e33',
                            '93c0bf5afad3b64e685a',
                            'a0e85c80e0551c9462d0',
                            'c84869f06c2635706e11',
                            'cb33cf4c72bf053052da',
                            'dbf0f48cfd3ab964ef08',
                            'ebf587f30ef1a52d0c0c'],
 ('baseline_consistency',): ['8b50e9cc395682a3a25f', 'd49c6db29ade7e59f918', 'd6d1e5ca4c83fab24f8e'],
 ('baseline_consistency', 'controller_consistency'): ['1e4c5f14c09afa5909f6',
                                                      '33d658c1734a3e10e9c3',
                                                      'c25fbd179b868b8c8f23'],
 ('bind_observations',): ['18365f8d4277c640e7d0'],
 ('bootstrap_scopes',): ['b267c1b342e3df584766'],
 ('canonical_histories',): ['327736f24171e660ac8d'],
 ('canonical_histories', 'bind_observations'): ['44e2f35501432107d147'],
 ('canonical_histories', 'bootstrap_scopes', 'monotonic_deadlines', 'contract_success', 'bind_observations'): ['06023a168e6aeafcafe1',
                                                                                                               '0a0f50008ae4279e7a62',
                                                                                                               '0c46d00e22df42487cc4',
                                                                                                               '0ea020923dfcef69a524',
                                                                                                               '0ef272abc8a30e359580',
                                                                                                               '1021f971b0ae3058d62a',
                                                                                                               '1174a15e89e284bc8063',
                                                                                                               '14f0e52c2514974252c8',
                                                                                                               '150c34b7b8cca19e32cf',
                                                                                                               '16be37dadfefeb7eba86',
                                                                                                               '1a4f08ec58c0b305d543',
                                                                                                               '1e7c50a5db9774ece919',
                                                                                                               '23005ec7f80da3312c7a',
                                                                                                               '241a7e36453b1f6fd6f7',
                                                                                                               '24a69e0de85c4c0788db',
                                                                                                               '25d4fa3e18e921ba3d11',
                                                                                                               '275171f1e91c2f9ed2cc',
                                                                                                               '2be85271f0629f36f13f',
                                                                                                               '308e3a40dd3c602555cb',
                                                                                                               '30cfab4ce046cf112011',
                                                                                                               '39bfa8f0c8bf8eb6b88d',
                                                                                                               '3c4afcc06af4f2c6805f',
                                                                                                               '4084cc8563d5e67f8212',
                                                                                                               '4199cc4b1b3155680b3b',
                                                                                                               '43df1d09fc1e2455e1a9',
                                                                                                               '4862ec46448b1ef86b82',
                                                                                                               '49581dedf64580a3d73a',
                                                                                                               '4a5a5d1493746de6d1d5',
                                                                                                               '4ba4d34db8000cc0c550',
                                                                                                               '511fdeb5b9f0c68cad93',
                                                                                                               '572fe5141c0359109663',
                                                                                                               '5bc482cbfcbe6a8ff83d',
                                                                                                               '5cb752d4446038f52b0a',
                                                                                                               '5d15fb6506e4ce9fa2d9',
                                                                                                               '699afa3529345a4f683a',
                                                                                                               '6fa45eaa0ef086e3a5dd',
                                                                                                               '710fc7a23bf0eff6414a',
                                                                                                               '7690685dd635ae977e9e',
                                                                                                               '78b8284b84541aacffab',
                                                                                                               '7b0831308da8b5161283',
                                                                                                               '7bd42534b25e1c959b08',
                                                                                                               '7bd7ce4e6b30b98b1e8c',
                                                                                                               '7f9d91f8531c36fb3240',
                                                                                                               '7fca06b5b6af34695bab',
                                                                                                               '817b8332f1fc7f691ed2',
                                                                                                               '82c14c9d4befd16a0e35',
                                                                                                               '891953a4b20d18d4dbc0',
                                                                                                               '8d3a19d55869471cbdd4',
                                                                                                               '936d847571933601addb',
                                                                                                               '96eea26d66334a5c6d66',
                                                                                                               '9753f64c7aa645867b6c',
                                                                                                               '9858d1d33aabb063c014',
                                                                                                               '9ac923084f89051bff1f',
                                                                                                               '9af162beebd03caf4000',
                                                                                                               '9b1ddabd5a23fac25003',
                                                                                                               '9e1e5b64717e6c3b909b',
                                                                                                               'a1acc685c049d1f86dbe',
                                                                                                               'a59275045facd97e4240',
                                                                                                               'a89f9c44b0354f9bcbce',
                                                                                                               'a9730406e02d0d45efa4',
                                                                                                               'b055b06ebb4cc05c628e',
                                                                                                               'b8c57fe8b1ef7497b58c',
                                                                                                               'b97fe1425682ba11b3f1',
                                                                                                               'bf819e8d3c9ac1fb5bd7',
                                                                                                               'c0f1102bb558eab9063a',
                                                                                                               'c46138ff91aed912ebce',
                                                                                                               'cb2432ac7f04384eb5d2',
                                                                                                               'cba66373b822c9509837',
                                                                                                               'ccd6b9168bd9525a9755',
                                                                                                               'ce8b987f09766aca526f',
                                                                                                               'd06c829fa54717898e3a',
                                                                                                               'd4c8e5b928cdbd448c09',
                                                                                                               'da265bd1bc954f07efdb',
                                                                                                               'db7175635144b316adea',
                                                                                                               'df4a976ed81c8889ec65',
                                                                                                               'e012b8f21ff9dc647eeb',
                                                                                                               'e3285c3f0ff41da8e376',
                                                                                                               'e533714de298fd702caf',
                                                                                                               'e61a60c9c107be951c41',
                                                                                                               'e6955598e3def26e420d',
                                                                                                               'edb4830dc59b77192212',
                                                                                                               'ef1e8d311b55856c88b9',
                                                                                                               'f1ad491d1c738640aa99',
                                                                                                               'fca9028b69a6631d1f2e',
                                                                                                               'ffae36c86c7b42d7cfc5'],
 ('canonical_histories', 'controller_consistency'): ['72ef8740c7d51633f2fc'],
 ('contract_success',): ['308031aa03bbc1a6176b', '740bd4dd6bc4f89546f3', '8636466385bdf4e05102'],
 ('contract_success', 'monotonic_deadlines'): ['3a72199020ccd619da24'],
 ('handoff', 'bind_observations'): ['2fc98548aab4ad6cd461'],
 ('recorded_emitters', 'bind_observations'): ['19cda0dbee8fa3c078d6', '7c01bac324589538a641'],
 ('retained_success',): ['53358e919a8d7e2f6cdb'],
 ('retained_success', 'monotonic_deadlines'): ['4e2db81e442001d1564c'],
 ('retained_success', 'recorded_emitters', 'preparation_success', 'bootstrap_success', 'bootstrap_scopes', 'monotonic_deadlines', 'writer_histories', 'handoff', 'bind_observations', 'contract_success'): ['0073f3232aefa7c6fa90',
                                                                                                                                                                                                            '028fd0a83755bba7641e',
                                                                                                                                                                                                            '08a7020d446cbcdc7a19',
                                                                                                                                                                                                            '0addeee2ad8148bebba8',
                                                                                                                                                                                                            '0e92069c9a7838dfa649',
                                                                                                                                                                                                            '11ed9bef0268efda1704',
                                                                                                                                                                                                            '13092e107a17dec6e0de',
                                                                                                                                                                                                            '18368827a21adf94ae4e',
                                                                                                                                                                                                            '1d43b2305f4ebd3bc126',
                                                                                                                                                                                                            '289b8fc85a255c197343',
                                                                                                                                                                                                            '2aeceeea263b68679034',
                                                                                                                                                                                                            '2e705f36963fe77f05c5',
                                                                                                                                                                                                            '3990a1b826ce4537231c',
                                                                                                                                                                                                            '3a6321575ea4b4a6b26b',
                                                                                                                                                                                                            '3bdaafcc52abd151c633',
                                                                                                                                                                                                            '3f545abf772624847841',
                                                                                                                                                                                                            '40d5e5ab59cb5d66ec5d',
                                                                                                                                                                                                            '4111d72b04ce34c3d696',
                                                                                                                                                                                                            '42bbb2c4ce15c04d3c93',
                                                                                                                                                                                                            '43fc327fe10b4c883c05',
                                                                                                                                                                                                            '660f2c0fe5223d599160',
                                                                                                                                                                                                            '6d4da232eb21916dc69f',
                                                                                                                                                                                                            '743931a2415e1ae64937',
                                                                                                                                                                                                            '75566e37d24bd2479a52',
                                                                                                                                                                                                            '79de54f4fd0ab7533fd6',
                                                                                                                                                                                                            '7c81a5739ec8e7bf046a',
                                                                                                                                                                                                            '7d6ce4ed75e2590b7020',
                                                                                                                                                                                                            '7e4cdd94fbed2286c1fa',
                                                                                                                                                                                                            '7e623661cf3590ef86e0',
                                                                                                                                                                                                            '870132859faea0156922',
                                                                                                                                                                                                            '8bca029c3a0c78f6d13d',
                                                                                                                                                                                                            '8bcf5cd7557f2a25592c',
                                                                                                                                                                                                            '91af4592330df8206fc0',
                                                                                                                                                                                                            '995430f0d08c21156ab0',
                                                                                                                                                                                                            '9a4ecc67854350e2d6bd',
                                                                                                                                                                                                            '9f0d6ff1e49d3d5de1e0',
                                                                                                                                                                                                            'a3b25dbd2e6dc9ca8af4',
                                                                                                                                                                                                            'a6c262ab7447739471bc',
                                                                                                                                                                                                            'aabfa9ae189a676428e7',
                                                                                                                                                                                                            'b1219d564171d1cc1916',
                                                                                                                                                                                                            'b2310d1fcd84729b1fd5',
                                                                                                                                                                                                            'b32b13fbd6483915f690',
                                                                                                                                                                                                            'ba317712ae72e8325a7b',
                                                                                                                                                                                                            'ba3c30baca7a50ff0afb',
                                                                                                                                                                                                            'c0109aa8e0731d49477c',
                                                                                                                                                                                                            'c7a1fef71a309fe6b906',
                                                                                                                                                                                                            'ca6eb474586e1e190a1d',
                                                                                                                                                                                                            'cb28f52ef3b7e3cae954',
                                                                                                                                                                                                            'd240bf0bcdeb45310df3',
                                                                                                                                                                                                            'd416d6f826b448e3127c',
                                                                                                                                                                                                            'da9a8264af3a3b115d3c',
                                                                                                                                                                                                            'db8d7b0f7764a4a19220',
                                                                                                                                                                                                            'dbf24f341f107a033326',
                                                                                                                                                                                                            'de5af0d2b15af2e96af9',
                                                                                                                                                                                                            'ee93c540c900cf3244eb',
                                                                                                                                                                                                            'efcdf18c1e8413d5d9b8',
                                                                                                                                                                                                            'f2acf9a04b18b49e377b'],
 ('retained_success', 'writer_histories'): ['5138abd2cc52a90d0750'],
 ('writer_histories', 'monotonic_deadlines'): ['3828b72abdcac6b2efb7'],
 ('writer_histories', 'monotonic_deadlines', 'recorded_emitters'): ['c99dbac0c3a8b813e040']}

OFFLINE_GUARD_REASONS = {'creator_or_pointer': 'The guard includes current creator PID, Rc/Weak origin or original non-Clone '
                       'capability. Those are not serialized. Any visible identity projections are checked '
                       'separately.',
 'live_clock': 'The guard uses the live clock/poll deadline or a running native process. Only serialized '
               'monotonic timestamps and original windows are checked offline.',
 'live_descriptor': 'The guard needs live descriptors, token registration, fstat/statfs, access permissions, '
                    'raw packet/FD inventory or a retained native resource; JSON assertions cannot replay '
                    'it.',
 'native_validation_call': 'The call requires a native Request/Receipt/owner/service/lease, parsed original '
                           'input, or live state-machine transition. The JSON witness is not that '
                           'capability.',
 'private_history': 'The guard needs the unexported full Record, original '
                    'PublicValidation/configuration/secret-input digest, or constructor digest regeneration. '
                    'Recorded nonzero digests and available references are checked separately.',
 'raw_decoder': 'The guard validates raw netlink/socket/protocol bytes or native parsing inputs which the '
                'witness does not serialize; only bounded public result structures are available.',
 'transient_or_fault': 'The guard checks a transient pending/intent/Birth state, failure/fault branch, '
                       'negative-oracle execution or collection transition absent from this completed fault0 '
                       'continuation. Its emitted endpoint projection is checked where present.',
 'unexported_module_state': 'This conservative module closure also extracts guards for private '
                            'owner/kernel/supervision/configuration state outside the emitted projection. '
                            'Operands are not present in the witness; no source-level execution is claimed.'}

OFFLINE_GUARDS = {'creator_or_pointer': ['000d6ecf8a8df5f0edcd',
                        '0048482e290341745380',
                        '005854408830b2d18eb6',
                        '00da76aa4ded0bd3e710',
                        '01c2d3920c208ef4379e',
                        '01ea041a01b9b61f0c0a',
                        '02a5b9b99cd8c7b8eda2',
                        '02e222769b785dfce8a6',
                        '03d2a3a8a26a49d835c7',
                        '03e0e77562defcd5a7b2',
                        '04d88195cb10e1097a30',
                        '0537e2e177d85753feb0',
                        '0554f9a040275576c289',
                        '070d8adae5615eb966cb',
                        '083c7d17ef661953efa1',
                        '08e4b2c3395a4bcd713a',
                        '090c808c0f5f199ccc7d',
                        '0953c19832442c23beb2',
                        '097e579ddf58cb9b46b9',
                        '0a060cbdbb4ca6003aa5',
                        '0c20f1e68799764a4de5',
                        '0d228c513c9730545a2a',
                        '0e9d3809d3c791dea5fd',
                        '0eb5e7fc57cdfff9d4ae',
                        '0ecb8fe64fea1edde202',
                        '0ee4e557277f5243c60b',
                        '11074b151c9ff5802f6c',
                        '113b2b93a2c3358cd89b',
                        '1174399f4ce6f0c7cde3',
                        '11916814091c28175f75',
                        '12cea2406cf1eea341a1',
                        '13b68212cbc5234a7ca0',
                        '147d3db48a7d30a6e021',
                        '150dfe0f7e2ea4a3e1a4',
                        '1537c41c3821acd9c513',
                        '1587f1f6c892d8a77401',
                        '165f7a91d34f656c1fde',
                        '175447ec5efa097bb812',
                        '176a0860e588cdd0062e',
                        '1784ab51e49c2cf82446',
                        '180490854af0cc70ccff',
                        '1880c8bb65c5efa16ec7',
                        '18fe20ad545205db548e',
                        '1b4b63dcb780c90c989e',
                        '1bcea72e65677266ea4b',
                        '1c25f6cea4f817f8bc38',
                        '1c64901bc6034ac30834',
                        '1c9e9a81dba29a1895b6',
                        '1e49cb1df21579c0b704',
                        '1f517c8a4b8496075ee1',
                        '21b206c3abd1e12cc9c4',
                        '228d4e645dc01953c56b',
                        '230808e891cd5c897b9c',
                        '234ee3f377df4ad84654',
                        '249e3f637e117a06d7d7',
                        '24a83ec0c54ced19728f',
                        '24ec990434bdfaab952b',
                        '2552bfc27cf5086525ff',
                        '2559023350a34f495e3a',
                        '256a0105cacecee2f1ed',
                        '256fab3e65127f6078f7',
                        '268e8fb45947d13a51c5',
                        '274c7cbff7009d9c7864',
                        '2771eefac5d639803ce6',
                        '28ebdf9a5100289ac123',
                        '295d223c32aeadd0df99',
                        '2a24235828539ae33b24',
                        '2a35a3b0d74a9a29040c',
                        '2b499e2f7b17b6b2d057',
                        '2dc468cd834cb38eedb5',
                        '2df8540765b781a6b7d3',
                        '2ef05ae118fb3fd07762',
                        '301b7d7562011ee01bb6',
                        '30208c0cb467eaa39c0f',
                        '30b38fbca8bb3a8df7b2',
                        '30d27b52698121963d94',
                        '317d7e0dddcf13a0b954',
                        '31a8840adc6b2ae3b868',
                        '32976c895e77692d02ba',
                        '32e729afdf97e2572541',
                        '3313f3c8fca4ee27401a',
                        '33364b9ded83852dc967',
                        '3349f013eac830e501b2',
                        '356fde1f7552b74a476b',
                        '36a6bd7aa2575d969749',
                        '36f814ac83a58f5b6949',
                        '370c9fd484d7a0227387',
                        '37378152f4288eacc319',
                        '3754e57067680b9bc2a6',
                        '3887a9d01880b7855def',
                        '3895387515aee9b43ce2',
                        '397620df9f08efd2e4bd',
                        '39f0ec0c8aec5cc1b632',
                        '3b136c851ba8543f5ac7',
                        '3b510657492df4ec1dd9',
                        '3be420bb26949f3f3ee0',
                        '3c0d0a0d8cb5c843d732',
                        '3cce402fede900f6ddb5',
                        '3e1bd849a7285c2f6d57',
                        '3f0d410c39c1747f60e6',
                        '3f16677b84c0f00003c5',
                        '407ba38382cafcf74c98',
                        '41768e886dae47c75528',
                        '41d559c502fa87091d69',
                        '428184ec4edb723652ed',
                        '42ac22c2ce77da8fae61',
                        '439753f0064942876c25',
                        '4522218bf9e959a63c20',
                        '4526cee70de71829e31a',
                        '453e66c3453f1a145e53',
                        '4560d58ed01b439af8d5',
                        '45c7688b85d0e377aa0b',
                        '45fdfc9be556af28a99f',
                        '466db1087fb81b56b21b',
                        '469a96a2e9b03dca502e',
                        '46a29769381e70cbf327',
                        '46aea49ac9aab07d2a53',
                        '48091c511dccd7f67209',
                        '480cc87f79203f7bb1ce',
                        '48833c3de5bb649a8e2b',
                        '499ed373412a66ac04b8',
                        '49e09faeb29465ad5f74',
                        '49ffac120f817808c266',
                        '4c0ac82ad83e2b298d7a',
                        '4d35a7f86cf5c5aae572',
                        '4da38d8fd279d7bcaf6c',
                        '4e93fa9050d2b305b4f6',
                        '4ec32924b0218760ac56',
                        '4eef10a78ed38f69bf5d',
                        '500e9285e13f09300499',
                        '50aac4738ed8a4a76457',
                        '50db1985340173984eb1',
                        '50f284addc7a823199f4',
                        '510d4cd711471b6dbf73',
                        '5119ae6c42adaa4268dd',
                        '52535121555bc2b85631',
                        '53bf12cd5f3bf2cd1890',
                        '53d2900e04cb8f1ced3c',
                        '54efd5beb4b477a0ba34',
                        '550b0d0b5cdbaf690f36',
                        '55b2fb53db809fe9ad45',
                        '55d86f0f04832b268ac4',
                        '561707683d6d02f0e744',
                        '56df310bbc32350f2b85',
                        '574f26aaa0a19f2c6c62',
                        '575ef6b0f0e557fff171',
                        '5a3436e59572db77021c',
                        '5adaaedecd1d8268837b',
                        '5b3964f91d54e88d49c9',
                        '5c37132797d5d847b50d',
                        '5c69e49aa8fde583af8f',
                        '5ef4bd3be7a0d805d833',
                        '5f490c5f8dfd3c886f2e',
                        '5ff1038d9f23873e6fcf',
                        '6077a6d5e1e927ee3bb3',
                        '608816c4a683ca31d1cc',
                        '6133779ec692e4645829',
                        '615fd6fd247f7a05acb2',
                        '63b242f6e12ced5390b7',
                        '6468dbe2a7f0dfdc9754',
                        '64f62220b4de93241164',
                        '6613dd61906240c20fb0',
                        '67498792a57d74146e74',
                        '674f2037ffcfd189736f',
                        '67b4c2051d32b158d782',
                        '67c61348cb87c2434329',
                        '688a287d49dc2a723d3c',
                        '69dc39d6e7f37a308f29',
                        '6a002277a67b00f80446',
                        '6a889149bedf5bd981a7',
                        '6ac3b9297edc2c6f46ec',
                        '6b7f38daef47d8be8b15',
                        '6bd4fb19c68c72e49863',
                        '6c20959a8f7a6691d4e5',
                        '6cdb3304dfbfdf7a39eb',
                        '6d67990845a2d6340a16',
                        '6dd490eb0149534f09a3',
                        '6f2c94de73682cff42a8',
                        '6f37a1951f0edf6d2ff4',
                        '6f3fb4202fc777aaad77',
                        '6f40185c263b0d3496b4',
                        '7026f9a8d2a86526f71d',
                        '714004350ddc81ea3c8c',
                        '71c883d182c0603d890a',
                        '726e92dbc0a4573b3828',
                        '727a43a171f437ee2e0b',
                        '7280e4772a4e15446445',
                        '72ee61a26712723b487e',
                        '73233a28f897d2a7429f',
                        '73e026ee2ee3967296b1',
                        '7593dfdbd8c27f404492',
                        '75b40fab514284d8e317',
                        '75e75f47b85c1adbbd7c',
                        '76228997894247af800a',
                        '76a3a0e7b3c2da26e767',
                        '7720093c746b10eebcca',
                        '773e57aea5d03507cf07',
                        '77ee67a3f4f5a5e3445a',
                        '78cf72b8d4dc48d03121',
                        '79a14ac28f6780dd267d',
                        '7a390ec50d3f898b6029',
                        '7b4afdda75930856a11f',
                        '7b6f2cdee85d61691dc4',
                        '7d745198bb083339d864',
                        '7d7e9aa8d77f04bcde66',
                        '7deeca1d136a7ff91f75',
                        '7e91987728d4323b4807',
                        '7f89447a12fc90a98366',
                        '800175052b2053c9a6eb',
                        '802daa67a3f7c8cc1454',
                        '8044554e622015e25104',
                        '84ba76f0d0cefa39ea34',
                        '84c095f11df5c67adb8d',
                        '84ff778e742811b13943',
                        '850c4433532370dca044',
                        '851413b281657d67d127',
                        '85230989a57356c34eb6',
                        '8706ed43e173e53f23b4',
                        '884182c85e0e329c0706',
                        '887975a8151b1e8ffa6a',
                        '890de4a76da2e1b2a3f5',
                        '893be4d0ff33b1597caa',
                        '89cb30f8b0b23e3eb23a',
                        '8b98a36527e976d2e48f',
                        '8c1ee76d31b82ca5c8de',
                        '8ca538f1c8389c74ee27',
                        '8d29a0b928f1e8e0f726',
                        '8f1023bb67c2655c5e24',
                        '8fabdc2b57db591bd4f1',
                        '902098da6d3138771db2',
                        '91487360d3726e3d3a98',
                        '92acb5764f0d202f8f7c',
                        '92f5382067ba6d15504f',
                        '935180975b7d0917b4f8',
                        '936b5dbf685b5c1683c8',
                        '948ca3deeaf584bcf3b2',
                        '95073450f63f7ecfdc91',
                        '954a2346c9d704d6704f',
                        '954ac06bdcf7baf13f98',
                        '9582d61b59e93eaa81d5',
                        '961961e07b6d520ca2c9',
                        '983f660ea1296dd9c5d5',
                        '99989d75815ed95809a4',
                        '9a786cdfe0af35e7bcc0',
                        '9ab5b218d7c9edcdd139',
                        '9af6cc66783452bffec6',
                        '9beca8f60c1581973f06',
                        '9c30f65469ad82338966',
                        '9d103ca8f93fd2cf9f53',
                        '9d23ac90d3794e1ca970',
                        '9e72a1faa34ba6c02dc8',
                        '9f83b8589e00ab295d4d',
                        'a182d6ad9428a02234b4',
                        'a189b528060d1643b2a2',
                        'a231333575a131da4cbf',
                        'a2f6714c73d7e25cfe82',
                        'a3647f1afd6272a506b4',
                        'a3b232a811401b693759',
                        'a3c0bb96166eb2c97f9d',
                        'a44fcba50aac6f187d79',
                        'a4f40202dfa5ffc046cd',
                        'a584ce71f4f5519c1938',
                        'a76eff8af7231bda1ce4',
                        'a7b0436c4dc7c7ad0e27',
                        'a7fa9651e84a0f13fdaf',
                        'a98b5753ff182f6fa491',
                        'a9d5b56a2770b90f6c45',
                        'ac299b874e3cf5903d9b',
                        'ae3f3a7ec4815a50f0c8',
                        'ae59f25a35f6d33f4d9d',
                        'aedc975a1c619ad7a1d7',
                        'b0446c4123dca3eef2c3',
                        'b1268aa812e202ad4e91',
                        'b47cae8e65f0fd382d3b',
                        'b54214f78ccff69d82b7',
                        'b556f783de3d5f8e57f0',
                        'b6a4f9eead6b0c82c845',
                        'b8684334ba5781104b3e',
                        'b99b044a8cd6e959194b',
                        'ba2099cdcd815b4cba75',
                        'ba5ea0ba482378ce6155',
                        'bb9958648c23a2ee3f74',
                        'bbfb4849763e70f991de',
                        'bccb8d5fa14a54f0c5dc',
                        'bd345dc842b220fe1d0d',
                        'bd3674687058ec9deee1',
                        'bd72c632bc108160f23d',
                        'be52365c551b621e30a0',
                        'bea82fc06b818cefc2da',
                        'bfd82b26549410a63978',
                        'c00284245a9818ac967a',
                        'c03c12a57687d7f76a5a',
                        'c03c6d834a938d11e18c',
                        'c083406cdf92d02bbdd0',
                        'c1f64a927b20b0405d6e',
                        'c32fba048f785d7d452b',
                        'c3fd94d3c3b1219f91d2',
                        'c44032a25ed2ab5f7c8f',
                        'c49c8f04393b4ecd6a50',
                        'c58398f583c6a8c3a4d7',
                        'c926d954ba87752dfacb',
                        'cda1104847016121888a',
                        'cdc171a7b70edb2677aa',
                        'ce2be4cf3757d51c0acd',
                        'cfb66ed2083e5f443736',
                        'd02edc22459f8369efc5',
                        'd363f839745b558a5dab',
                        'd3671506458d28ee33bc',
                        'd4190e6bb31a67ee7455',
                        'd5328d28c4e69568975b',
                        'd6d95ee15771a46789a7',
                        'd78674058f4555dc0c94',
                        'd8d1515bc2a5472137f5',
                        'd95064a107ef5febf6f1',
                        'd9863fb5da40f659c738',
                        'da8ea456eb156c85868c',
                        'db5d5a41a7d4e045adb0',
                        'db70f96a1162190c018f',
                        'df1ff83ba5586ed6ebd7',
                        'e03d330b648eb60439aa',
                        'e08c11f1e7ec7c160ec6',
                        'e1db62cea5d4af6efc81',
                        'e3bbace5e0dfaac75055',
                        'e424985e7fe5ea007c8b',
                        'e42e9bb0703ebc2e3798',
                        'e42fc78f2977658b0848',
                        'e4ab81b755da940c04cf',
                        'e5528f0c875e7cf24be7',
                        'e6f3061e44c33dcd6f85',
                        'e74ce9a64987475ebc5e',
                        'e80ebf258d241d4cb9c2',
                        'e81e9064d6ff8b2679d5',
                        'e84a372e8dfb1d067543',
                        'e8f757e0aed01a84b656',
                        'e91a548667a250b0196f',
                        'e9520097085dda983596',
                        'e99637754ed75ba8c2a7',
                        'eabc38d80644a96360f6',
                        'ec02b08a871f584f0d7b',
                        'ec96f21fe85cfd3bf6ab',
                        'ed5b789c2bcc02718048',
                        'ee0db3f71f4c01ba5ce8',
                        'ef328065e41156fbcd68',
                        'ef42b76e20cb8e898ea8',
                        'f006adbb36bcee1428be',
                        'f00fdecba6759819dd8c',
                        'f22ead230524607a212d',
                        'f2610ceced9f3c453444',
                        'f2a356ab31f139227219',
                        'f36215f985064a18c3c8',
                        'f37509d84b43deefcf3e',
                        'f37faa02dee9881d28e5',
                        'f3fdedd56816a65ee58b',
                        'f6a5f8adc4dff2acbf7e',
                        'f6f789db23c92175f8ca',
                        'f7ecb8bb1ef22704d8d8',
                        'f86e5af16a7cd8c5ff94',
                        'f8bc39d60db743c9a98d',
                        'f8d1653152cf443e94a3',
                        'f92e8500f7c51e54fc31',
                        'fabefb8c1ce0c6e328ad',
                        'fb7f5795a9f919da2da9',
                        'fb9386f1b816653cc82e',
                        'fd3ee886b4f232df0cd0',
                        'fe1b5ccc254b4e843be9',
                        'fe392389f3cc835f4609',
                        'ff10e0fd67c491685d12',
                        'ff2011f97ce728a4344f',
                        'ffd7010c706baf7b6d73',
                        'ffe79104611b2a7879d4'],
 'live_clock': ['01471743863f6d6c5c29',
                '021e29d4361802b6c705',
                '03da6c22807d508ed62a',
                '048a5f8aa5211329321b',
                '06136ad71692cf78fd3e',
                '06a09fcbc2b30e58f0c4',
                '08075f08e1d694ea8322',
                '083c0bbfe1cdd637867e',
                '0fcf69f6c1282f9aa576',
                '187bfbc129e48d33f1ec',
                '208a24b00cfa0eb1592d',
                '29be9c556839374af7d5',
                '2b3562f77a8c98c8a2ff',
                '301293a28bd565d34302',
                '3437f01c1166811e827d',
                '3a22f3c6ae9d04dacd3d',
                '3a657538017c1029e936',
                '3ac8c0848559ba748b15',
                '3ec670d2773e9eb42772',
                '4162bfa9532794e4c6b9',
                '48e277ef02d216905703',
                '4b30b278593e4eb1b528',
                '4cf9e3bfdf99bb1e46f2',
                '52b91e3bd99d54db6c98',
                '52ca57c4ecf3f9d7241a',
                '53fe8a9f218efd7fabd3',
                '5847468d8377bd0ed52c',
                '58793f8e8576442678d4',
                '5a8b0b5b8ee15340817f',
                '636855243dcd9f29af7a',
                '6945c625febc011f5558',
                '6ac84bdb349ad4048d78',
                '6bfe8905240aba4dff83',
                '6d751760d6fc6b990c0a',
                '71a0da34de467b887765',
                '7375c541d987236cfc08',
                '74df3c7aac83c7559982',
                '76109679f7f623ec3bf2',
                '796720f56419078c168e',
                '7ace2db76e240d517b11',
                '7c59c0f6069689a2f34c',
                '7de566c2e61311ff243f',
                '802185ab7818168ef010',
                '838a3d93623f0b999a38',
                '876d6b30ec2e42601a02',
                '88594b73000eca39d405',
                '8c2a38615cffd127739d',
                '8d7d69b6253ef845c706',
                '8d86ba8a7efc2c543aac',
                '8dadb57569a3a774ea0f',
                '936066b2a23833241182',
                '9655b9937187f77cb06e',
                '991a59f276d50bb25612',
                '9a99498712a3ebcc884c',
                '9b0ca0caf9f19109a23e',
                '9c7c3fd8c0530a10d813',
                '9d3ca483049c3d3f8156',
                'a18b9441287e2ca64725',
                'a77f49c14ec00b60fb1f',
                'a96899e9c73d8b41edfd',
                'b2dcfb08b197b4117f4c',
                'b396fc6e3df0df5d2631',
                'b5d3fe52cd8d37ef7c97',
                'b8f80ba3362af9088693',
                'b9ee828605aa2b968179',
                'bf8e1e0ae88969e2299e',
                'bf9f7f3ac5eb5ab85e39',
                'c2771357f07a130891e7',
                'c27ee934d5e3b76a978f',
                'c335ab2d6ccb9fdd2bdb',
                'c34bb065f79e901c2c84',
                'c4bc365b8bed08bb55d6',
                'c9476a45a49494777aea',
                'cabfa760d8d34957994f',
                'cb25822a1bede4658a23',
                'cbb71aa10e39825fd7fd',
                'cc394812efd61ac6587e',
                'cd476f42adde4575369c',
                'cd50d16dc6f850b0696b',
                'ce6b04759f2c02baf882',
                'd016bb00330bee864c5e',
                'd0ed8a71f9950718d440',
                'd26458746c0b647db16e',
                'd3b9bbe9eeee968e06ab',
                'd43303c7b267b7b7ecf2',
                'e00da4ffbe6790d2f765',
                'e00e6808a110b93a0b21',
                'e197b27ca70fdfc31c6e',
                'e1dbb93cfb16a59afca8',
                'e65d596397c901f05f7c',
                'e7180da8ca016c68d6e1',
                'eb42fbf211e18a7882d9',
                'ecbaded485aa9de574b3',
                'f369c5f8cb43e7d51343',
                'f3cb231c093c25ede627',
                'fbca70d4c6ca3e465330',
                'fddac942e53be4c50fbc',
                'fe791f0f856c532b0c03'],
 'live_descriptor': ['00e5538740fa504db935',
                     '020c70ef75c968d79451',
                     '03267e9aaf75530bb180',
                     '03dde759dc018713bbb9',
                     '047f1a10b2d5d8da9f29',
                     '056ba3b29edafe272a08',
                     '059cacc9dae2bfb36382',
                     '062e46bf044c1f50d886',
                     '06abce3e9d811732de22',
                     '073adbbfb74ad775f2af',
                     '0757e7db58d0fa89d1a7',
                     '0763405eab68b977acf8',
                     '082ce5ca3a1b926ced3c',
                     '08ee1299b7f882fbedcc',
                     '0a63158fc45340e48663',
                     '0aab9f6db7fbfcec1bb1',
                     '0b7063f2800ea95a5aef',
                     '0ba93dbad2b9fddfa41d',
                     '0d8fa06264bcb800f200',
                     '0da3343d206af251ee38',
                     '0e28e7bedf3b1c223aa9',
                     '0e2c50f196ff677a00d2',
                     '0f5032d2aa5989a46b8a',
                     '0f6ad3d7a04df294b239',
                     '0f8e21b7ace46673e5bf',
                     '11a212856410c7067aa3',
                     '135cc342b2182984fda3',
                     '13add5ed2a44308760a1',
                     '14008573d6ad7e17477c',
                     '1442c23de3c9adcc2d17',
                     '149d578c08465895ecd6',
                     '14f68397d3d3ae860194',
                     '1648810dccd1cb328291',
                     '17931093f687fffaf2f7',
                     '181393c55ec016e66080',
                     '18ebcad8bc030c7f0022',
                     '18f3654559cbbbd0bc96',
                     '192a63a31645ff402cdd',
                     '1a0ea44ebc523d0e24ed',
                     '1b20a9cd241a1fe52724',
                     '1b58dfb3cb2ada7f38df',
                     '1f1faba7b57d6ca20e97',
                     '1f7d55b8cabcbf933ba4',
                     '1fea7eda3873d998d738',
                     '223c5f5a67c581986958',
                     '23b998df9c0607d3e69e',
                     '254a71ed1ac306322e6d',
                     '254ea7dc4ba492f7a0bf',
                     '256ff26e265df1c31b8a',
                     '2766a2781eb5f4ccd8ad',
                     '29f45d6e20e37c0dd50e',
                     '2a3d297f80af80cc838d',
                     '2a777bf12206a3fb2ed2',
                     '2ac2c38c8e862214661a',
                     '2bd68b806629acc4d8ac',
                     '2c41c7305252674bcd2c',
                     '2d3288140f6cee41a164',
                     '2e17d7386b0c454951b1',
                     '2e9a2d68f325e283f43e',
                     '31a0ab710ba23116d144',
                     '31ed06772f12c9d6e2a6',
                     '3211f773c1b29808140a',
                     '32912e5c434006f0a659',
                     '35e9398f0d342e494fda',
                     '37a8ddb72948e601abec',
                     '37d2994e0c8c5a66f9b4',
                     '3839a2cb181b9c22b0cc',
                     '38dbc630ef4b322a65dd',
                     '38dbd321a5569913a100',
                     '3b67eacaa928899e0fd8',
                     '3d5bfc8e19fdbee837a3',
                     '3e2d8d3c3c871ceb8dd6',
                     '3ed7ff80ac33929fd171',
                     '3f25f8fa4b92ff5e50df',
                     '3f47853774e46187ff87',
                     '3f62cfb836ff4ac067aa',
                     '3fc122c75d0ea66ceb67',
                     '401704b155493935cf83',
                     '401ea0d80abbb2e61dfa',
                     '40ab1d8e58fcdf6dc4af',
                     '41d302fcbed82c41fea2',
                     '4200ee5700c3ae3a42ec',
                     '42629723dcf09ed2d7cf',
                     '4297fc6bcee3573edceb',
                     '437ac32c05fd273c8b53',
                     '4392c136fdd34c2bbb28',
                     '44055c97ec294b14edd6',
                     '45acc7bb76fa2dd5886d',
                     '478f0e2ab4f8a297e564',
                     '47d55796dd8382794fa9',
                     '48a6649bc50eb1f8e386',
                     '48feaa0adad9e90990c1',
                     '4a0cc99a71d32cb27ee7',
                     '4a386db93182094a29df',
                     '4a99c91e91dee9cb2ba7',
                     '4b8a46cda37185bcc546',
                     '4c85f1806e21073e80bc',
                     '4c8e397d929698e81e83',
                     '4ddf9b2f273192cbb2a8',
                     '4deba6ffcf849d8bf025',
                     '4e6d5686547d4a38146e',
                     '4ebb4a306c2040136cd6',
                     '50d970f1aa8e2573417f',
                     '5109fc06f20a03026224',
                     '5171d86693112a023b01',
                     '5210422300b02e4b38e1',
                     '5229a4c51eba0e394d8e',
                     '5314de47aee10298e5e0',
                     '531df0401e0f36b2a8a8',
                     '533731c501e3de70fdfa',
                     '541e617341be51c14ca3',
                     '54dacc392a15886d2cac',
                     '54dc4b9df9880d969b62',
                     '55480967baf030d705fb',
                     '556b166c6db2221bdb56',
                     '55bbe81d74873788597c',
                     '58360efd3d977d44ce76',
                     '584c700c14df2fe6cf02',
                     '5a085dd42c3d54f24f3d',
                     '5b188c362d91126f3e49',
                     '5b196e93cdee3fb06fee',
                     '5cb06b9cd283eca0af80',
                     '5cb20fe84ff021de8162',
                     '5cffbb1ed6b183f937a0',
                     '5f9a77bd6df311289e6a',
                     '6159b68d1e5e4d56c275',
                     '61d3e5f5401aa948ad4c',
                     '61faa1b3b9acedbf2dcc',
                     '6450c0ecc5d4d65fe673',
                     '669dec57ef254f2aad65',
                     '673d9c131d508ffd2a82',
                     '67969219d2db2e07363a',
                     '68b93aa9ffb07b76970f',
                     '68bc960d87c89689725f',
                     '691eec710e324ca6fdf6',
                     '692585694ccc3316003d',
                     '69536eab89172f8adcbd',
                     '695eede10c6de068dbab',
                     '69b4f4a8ac612207f3a7',
                     '6a00508405b8de77f335',
                     '6aa7fa5fa7cba93ec30f',
                     '6c00831b00b162b7737e',
                     '6cbe3a9410f9c9f56803',
                     '6cf46a7798207af30a3e',
                     '6d9ece5c1ee87504d97f',
                     '6dc82f642d77dff4e45d',
                     '6e9315cf58fa71871b12',
                     '6ed2ca75f5325da5e21f',
                     '6f8c888f57d695910922',
                     '6fe0a39163873e18c5b6',
                     '703ce9e580c6bdc1ee9e',
                     '72866239aa068a754145',
                     '72a29b3d577321fb8722',
                     '72fcd93bd7f60cd61de8',
                     '73be694d9d979f0715d8',
                     '73e596c45f5bdc75ff46',
                     '75577b731736887a0627',
                     '778ff742d4a53e57b373',
                     '781cb928fda5ee0f29fe',
                     '794c6e0a082d46935126',
                     '79968c511fd20dabc28b',
                     '7b3337c050f23868af42',
                     '7c6effe99a5b93d3b8a6',
                     '7c9545cfe32cd0fe5880',
                     '7d2c46e4b16e9e77ee45',
                     '7d61cdec2722fe1c6956',
                     '7e3e95b2f05001603288',
                     '7e853d2971cd493cf603',
                     '7ee407ccd0cc080d41cb',
                     '7f4ac8b37a3f093b501d',
                     '8120609feb78f9826b0b',
                     '81d5324d598d43be6cc4',
                     '82830b9c664c765afa3a',
                     '834dd8114ee3661426a7',
                     '848dea13b18c00c9a08f',
                     '857459bfc7aa3a11beac',
                     '86097ac84fc3ab1ba4ec',
                     '87252e89031360c926fe',
                     '87c4eeed292d99c1bb6b',
                     '893342fb3b14d8a01542',
                     '8abdd4c2fdcc396b2744',
                     '8b36359a48eccd5d466f',
                     '8c3003ac994cc17405dd',
                     '8c847c2391a598c5fdfe',
                     '8cb1247b0cc442a973f7',
                     '8d6c2e230eebf349debd',
                     '8d7dd5b4c426fcaa8a04',
                     '8d8ade43fa15b859c64a',
                     '8e8c046cee4891dbb3fb',
                     '939a95044e02d58e9bc1',
                     '93c44ed76ca91e1f64ea',
                     '93eee96e6564b00d95de',
                     '93fb8108b8fa6590aac0',
                     '95f5ebe37fa26e351992',
                     '9613c67992463a4bc55e',
                     '97598956006594a7daff',
                     '9b863637f9ee017198a5',
                     '9cb8748f389a4c3ad22c',
                     'a2cc1f305b3958d91d8d',
                     'a38a16426c8cb33e22cc',
                     'a3b04fdf61a4456867cc',
                     'a6ddabc7f7713326a836',
                     'a6eb1583f10447c35c96',
                     'a8167c43e0ed4f230428',
                     'a822f38b9e88f3f4ada9',
                     'a8f047b897f018ed1c06',
                     'a90cb821bad54fa10b6e',
                     'a96b067228348c2e6cf3',
                     'a9aac13e65c46d232796',
                     'aa784fecb3f5a4ac1e24',
                     'aad491b192469b9a47c8',
                     'ab09b86efe188599e22d',
                     'acce71c31c481b670894',
                     'ad2f1913f8a04af77a61',
                     'afec71e90692f0d2356d',
                     'b01486d89d55a9fff3f9',
                     'b16c1bbcae9f4735b45c',
                     'b2140975ade9770e7d96',
                     'b2395c69886d2f0cc11a',
                     'b293bc039d3e0440f207',
                     'b30f1aabd556f6f4566f',
                     'b6a882d2444026aac84d',
                     'b7190dfe7d3e7cc6e8b4',
                     'b73f2985ed081e797505',
                     'b74043eec3b747c2dc8f',
                     'b7db7748b2cca2a929ef',
                     'b939533b87bb62746db7',
                     'bb7e36510d87ae40b9c1',
                     'bc4c2598e6e41dac8e21',
                     'be1db6d8d9cedaf8823f',
                     'be5b89f77f83283ce7f9',
                     'bfab53eb3e3ede8c4cea',
                     'c036d3af7d9d0d6d3f37',
                     'c0df115aa7239da5e6e9',
                     'c136bf3be989737dfe9d',
                     'c223fad4d8056d6187b4',
                     'c2500bfd69f4fee2bb30',
                     'c3024e06943ced148bbe',
                     'c4a53d6d5fb330a2623b',
                     'c6178803b890925a540f',
                     'c72f28e3f14399c8cdd0',
                     'c87b9c16f07fbd203635',
                     'cae71c17b2e286f4ed4c',
                     'cb1fa6c825a8d037a741',
                     'cc0b7d405d01c3c36c27',
                     'cc7b8e84e4e64d4c3cae',
                     'ccae578d3cf9aa1c6c81',
                     'cd26c3a648e1b14b69ad',
                     'cf65ba7e910feed0c99c',
                     'd0510e269f7b0a52f96e',
                     'd1fde3b0dd4daaac39f6',
                     'd26ef1d343cd47155aee',
                     'd3187deb25df5d843f98',
                     'd3a9f929f24a2c8c11a9',
                     'd4eef1875c31d88b2421',
                     'd5b4507b2262f8649f1a',
                     'd698b105f2a86092aace',
                     'd886c498d67666a33d23',
                     'd9b1d6960d29e55ec6c0',
                     'd9e203d2ee40e5166d55',
                     'd9e931ee2ca9997bbc9e',
                     'da2357531d6db2b54e54',
                     'da5c1d900744fab19c47',
                     'da7b87878b6559f90e66',
                     'dacd84d14a2ae35dde75',
                     'dc3fb0038bc3ab460646',
                     'de3adf6ad151d353c792',
                     'deb969536a6cdc465c10',
                     'df16b33708efd5b54ccc',
                     'df48a247195d226ee191',
                     'df8b64396d71a4807d72',
                     'dfecdfd8d9b82f8ab288',
                     'e168634838296497553b',
                     'e2466e69acde4ef02c52',
                     'e3f53dd6d31c9b9a4514',
                     'e49ed7d4981173720672',
                     'e7969791066d101d033c',
                     'e991fa09d3abb8830151',
                     'e9e5a8ce1edfd4e92e43',
                     'eb7efd11363f8555d09d',
                     'ebfd57117ab4b5867bc7',
                     'edb3da19b7acff974569',
                     'ef62b32fd720a7bbf93f',
                     'efea9ca8de24b1a42536',
                     'f014ee31417a6fc5c7e1',
                     'f0e430c8df76419174b6',
                     'f121a1f6e32964824c0d',
                     'f21ccf94bd32df21fc7b',
                     'f2470e370931b2ef0997',
                     'f29cae346d9b592656aa',
                     'f327b5b8fa096e774808',
                     'f378492474e18b73c263',
                     'f5dc293c92eae4f7030a',
                     'f6b06dbde0e28c76c7cf',
                     'f6dd64fb5f1eaa634cc4',
                     'f7aa578a16832d4e7789',
                     'f7db4e729ea121b25472',
                     'f9288910d9fc9e05195a',
                     'f946de4a5c7dfafefbe5',
                     'f9f904b85d6bfcb62afb',
                     'fc4225cda46ef01fbc39',
                     'fc8d753a629d3a6ed905',
                     'fd7f72ce6627abe54607',
                     'fdb62506200cc4d4f469',
                     'feccc2d24703b3c3acfe',
                     'ffc445707b3172c29a7c'],
 'native_validation_call': ['000aef7f0625c715e874',
                            '00c5c0176e7c96ca3f37',
                            '00d2309b2224e31e1f9e',
                            '00ef9a7d50c7dadf204e',
                            '01098cffbc38bdb42ba3',
                            '01163d9689b0f7ad9205',
                            '012ab253c2ac8614ad94',
                            '0190443d4ab2468038c6',
                            '01abcd92a68f38eac3ca',
                            '01f6db4ecfa0ad602615',
                            '0225b6c70c0e3ce33d28',
                            '02ca2c61a30bff4a7e4f',
                            '02cc75e2dd915dd8d822',
                            '02d271096f0d07d50301',
                            '02d4b24a9451ea4af9b1',
                            '031a1581be5975e73550',
                            '033510dd31d5fd7be38c',
                            '03419c1be1a21b266466',
                            '03560188030fea185284',
                            '0398233720573186457b',
                            '03ce61428f5c03dc23ec',
                            '03f10064975f4c1177bd',
                            '0474132bd5f6c4c4b640',
                            '04b876d5d33d6f039bbc',
                            '04d92a0413e5b37c8611',
                            '052f7a797ffbf1f57314',
                            '05347fb1d11cdf4519d4',
                            '0547300e244df56c89cc',
                            '0560d757ee0113103cb5',
                            '060dc96e796b8b97b769',
                            '0634e800c4e34510576f',
                            '06375e65ca8204e4a5e4',
                            '066afdf1bcfa3debd6c0',
                            '06a0acfa2a0b3437735b',
                            '06a40a10fb93f009a9ae',
                            '06b1c403717e25c38233',
                            '06bc683d8faab2509eb3',
                            '06e7fbc5da6674a422e1',
                            '06eaa48372ba5e533873',
                            '06f81aa8280a688f1f9e',
                            '06ff692716d1c69c0db0',
                            '0705d1d3b6229690e874',
                            '07f2d63027d8080511f0',
                            '08509d0343521b5671aa',
                            '08697da55f7880dd01b1',
                            '0872679f66f5de9354b3',
                            '089ff4d1d617177f1cf8',
                            '08ae4176b03ed8fdb8c1',
                            '08b103590efdb08080ed',
                            '09bf957b5c20fa87d29a',
                            '0a03d63da065e7c96abe',
                            '0a0c9e2deba7707800ad',
                            '0a407f326be1af848ff9',
                            '0a7a1bb5f5aab46eb9b8',
                            '0b0ef66a82ebcc25d6d8',
                            '0b1b314f5342361d9a29',
                            '0bb886716d087dc6387b',
                            '0c223de9d0b9b01d3aa2',
                            '0c6771d2a748b5ebbacb',
                            '0ce1c74923a56b66c6d2',
                            '0ce790e4f03e823407b0',
                            '0d0a5ffa0207b9260bb1',
                            '0d0c830800d44a8f7188',
                            '0d5f31aeb761718bf00c',
                            '0d6483be4e40937c3f24',
                            '0d7c9406bfafc764bc34',
                            '0d93760bde9ef706280d',
                            '0dbb3390aa022e3a4b9e',
                            '0dcfc099dd9bb6037f5e',
                            '0e05e965afe68dbd62be',
                            '0e66200c3d3a57d1889e',
                            '0e75f98c17cf1ebbfd49',
                            '0e7e175b2686cf5434c9',
                            '0e83d142c9d7cb6a0be8',
                            '0e8de231a7e232bba6c3',
                            '0ea7ac65007ded9a51f5',
                            '0ec01c392519c58cdcb8',
                            '0edef2833fafe41a5f8a',
                            '0ee12ae88a2817315234',
                            '0f1fcb49eb2df4a86d49',
                            '0f6ac2a40cdfb46e1e11',
                            '0fda3466b064ebf40f0e',
                            '101224b09518a90a7038',
                            '101de26af02d9ae92bb6',
                            '101f3de8d5457e9ba4e2',
                            '1089b1c988f41d1fd9ea',
                            '10f0dee1c669be8d122d',
                            '114e6e72c3075094c744',
                            '116bd2283c7a780a384f',
                            '1197a373d7f3a331a59f',
                            '11afe48f20dc2014eec3',
                            '11c8a9bbb7ac681c76de',
                            '11e42c923be40368c4e4',
                            '121a304707a0f4d22055',
                            '127267ad0404bd789b28',
                            '129f686b032f432a3e96',
                            '12d7ba2b5026423fa8df',
                            '12ebaef7267b0e783250',
                            '135bbff8ecaed3f51c2e',
                            '13832b024d70c8d3a851',
                            '13a27a909886f59ebd19',
                            '13f14994290345c3065b',
                            '14052e357a7bfaf6b874',
                            '1409a0ee7c9899d96fc4',
                            '142e39c904be182fae8b',
                            '1448c92d99d56d80f2a4',
                            '15ad298411f22465b783',
                            '15aeb73adf18fdb7383f',
                            '15d5631270edc2eb81cc',
                            '16affe6b7761a328960e',
                            '16b44719bc3e1b879065',
                            '16d1c004752ad543ce3c',
                            '173ae57305a0ec0c5ad3',
                            '173f98cfc2802e1dd5fc',
                            '176b487198a9f0df8e23',
                            '17a378b7d53998ae540a',
                            '17c9a4049970335fb471',
                            '182f647359917c8ec0a0',
                            '185e80ac9a586faca24a',
                            '1881fa09a32d0c4a87fb',
                            '188e0126303edfa1516f',
                            '18a7d9367b8b2eca2f63',
                            '18ab372d525e06e93ac3',
                            '19049da459c82f9c63dc',
                            '190c307d2551d69cd1a9',
                            '194f6417676172ee65ca',
                            '19905d8ff0cffd038a87',
                            '19c18ab586e6b3034ffd',
                            '19c36a62620790d8d149',
                            '19de4ea6416c9d41404f',
                            '1a2680610ff3b519b48f',
                            '1a42c7738b17c9cc051a',
                            '1a62356740f3d673958b',
                            '1a90faa5f65c1ed6a808',
                            '1ad5cced52b068f940b7',
                            '1b08350983de5343e937',
                            '1b521993b576cea19f4f',
                            '1b8dcaf8659dd6cdd6d1',
                            '1b95438e4c5b5ddb0277',
                            '1bd7be18d44efea78a1b',
                            '1bee525146c544c53cab',
                            '1c10f3c315c606c968d6',
                            '1c2e6e7e449db697bf41',
                            '1cb2302f896eb5fc5cbf',
                            '1cb820e6d320ffa0c771',
                            '1cca511cc3dbff523704',
                            '1cfc0257bbf1a8d0b36b',
                            '1d2530215d8e7d1ea769',
                            '1de0f899b4a989ec19b2',
                            '1dfb665a24c40988603b',
                            '1dfdc230c7cf89f4861f',
                            '1e473f470c12d43c853a',
                            '1ece09831eb9cd6987df',
                            '1eda6303ea4a9b19529a',
                            '1f6861e478a0c0e8981f',
                            '1f7b317398ba3cebdad1',
                            '1f845c1ddeca17945168',
                            '1fa0779d7038b190cc9d',
                            '201604de622b1836ab8a',
                            '201be5af704f8c59e7e6',
                            '203f01a9c9030b17e7ce',
                            '204447885e445c378e65',
                            '21119baf90887db66fb0',
                            '2111a0a741b1d47676a3',
                            '217684a55f7fab45024a',
                            '2185f4d0d6cf955fb5a7',
                            '21ac2ef0b93acd502ac1',
                            '22040619f3ad973d5c21',
                            '22ab6f99ec163874d2ad',
                            '22b5c212b9e0dc85f565',
                            '23210c65c81711bbb771',
                            '235d2b2f2b479469244f',
                            '2360e8a6a2e5690bdb0f',
                            '241b7275c91498128eee',
                            '249684dc43d1e789d303',
                            '24da4d23367f04c4b4db',
                            '253b95530e4ab72f7c99',
                            '25580316e01ab256e2c4',
                            '255eca19e42b7c0bfa52',
                            '25939975fcdfa2967431',
                            '25b5c4a6892236398c03',
                            '25bebd09f443c8e2d1b9',
                            '25d245f8d42efec14674',
                            '25e051a729a1cc861e0f',
                            '25e43cc73ed5eebe1ef9',
                            '25f93b5872f7b2288482',
                            '263c8553c9ee61ea4e33',
                            '2641d66662d7856760d2',
                            '2647b8a4b80e3e6a9e41',
                            '26e9bcb98b53b83e5a30',
                            '2713e12cc335cd5ddaf3',
                            '278c1463856f94de3070',
                            '2793b3b5ced72734a6cb',
                            '27a160925c98fdd5a7a9',
                            '27ed1fede3721161866b',
                            '27f9d590757f759b8425',
                            '286a26df8b340d11da84',
                            '2872bfc135b9e2b7c110',
                            '28a7503e0921323c30c1',
                            '296fd8ca0e71fa458d59',
                            '29a0d24ecab7c6b7c35c',
                            '29df7ff7281642940ebf',
                            '2a07298e3a152fc85a4f',
                            '2a3fea13cde751c581a9',
                            '2a45862afd938a5c4f5e',
                            '2ac41a4838e6440d1c0f',
                            '2ae8abb7ccf1212ede63',
                            '2aeb4c1eb536fb69900e',
                            '2ba997bb78f7970eb582',
                            '2bc4e086b751eb3ef142',
                            '2bf9ba2c4c444eb57c59',
                            '2c561399e0902a16bcb3',
                            '2c5b17359d0f33f1c851',
                            '2c6c6dbf3df60b2f07bc',
                            '2c824a52a87d35bbb68a',
                            '2ccae75b2157709fc0e8',
                            '2cd645e11d218e179976',
                            '2ceb5912ac2bec04cd57',
                            '2ced4075d105716aa110',
                            '2cfc29ae0599f8d80bba',
                            '2cffcdacc641b35ddc81',
                            '2d3b6474494a9a452d2e',
                            '2d48feb80ceb5a966a55',
                            '2d4cb9bd2f2ff1aaf506',
                            '2d69a7f731b00480098f',
                            '2da845d45440daf285f1',
                            '2dbd03c7638f54d7ffe7',
                            '2dbeef9c9aa20f8fb91a',
                            '2e7cc28302b8ca2fa157',
                            '2e8d489253632981cb31',
                            '2f07365a24148cbd770c',
                            '2f63c74fd1a1b5495a49',
                            '2f66944321ae9a876cfc',
                            '2f896c1cf9ada433247e',
                            '2fc0f3b3edcdc4a972d4',
                            '2fcaedf4fd81fa9fe6be',
                            '2fdfdd6dbda749c19bef',
                            '300d27df13272f1b98a8',
                            '305332796239d17c0a08',
                            '306c17c02c65300ed802',
                            '307dabd6c6eb324342de',
                            '30b37ecd49f992852ac5',
                            '30ef2dc5b123c9a4eaf9',
                            '3182bef1ed88f4a5a1a7',
                            '31a153f15e428bd4cf76',
                            '31a5147e24f1894d24f0',
                            '31c47dde4062fd461091',
                            '31ca837fcaacbca19a31',
                            '32cb6e5162f733e9a6bd',
                            '33bd0e446045cffea139',
                            '33bec0875ea4dc4e6dd4',
                            '33c5334eceae6efb9671',
                            '33d6a95e6e6ddeb72b07',
                            '33d7bcf21e5393116298',
                            '341104d6fa14d839611f',
                            '341a8c7317692ccc2074',
                            '344885d9e0bc9b53baf9',
                            '347db3d28a5c670bf8d0',
                            '34878991634b9ca54319',
                            '34b35f7a672bdeb44474',
                            '34ceb359642bce3e4b28',
                            '352f5b0ae089c19b6d2f',
                            '35350d0121ade4d20889',
                            '353713f343f563c29b40',
                            '35535a941605bf08549b',
                            '355af9dabeb933581bf0',
                            '35fb4cb75d5868ee451b',
                            '362f9991166c79a1b843',
                            '364e36c962ba571c38cd',
                            '3665d1439d9f7fed4fb1',
                            '36826ab53cbd9ce268dd',
                            '36a63b55ab88ce7df54f',
                            '36a8847e079ef6950f4d',
                            '36b8af30e5d347972e67',
                            '36e65a6b67777b6cb769',
                            '3729b533fe48663d7f79',
                            '373dfa4b277684755c84',
                            '37e7d9ffd93c3cb183b5',
                            '381d54aa98c2d9b966c7',
                            '382462859c69db9e6fb5',
                            '383bd586c89809f1264c',
                            '38601a75ec6122fb171b',
                            '389e5ece2394ba80acda',
                            '389e74c991d7a8bfc8a9',
                            '38c4a861efaa82d82ce7',
                            '38d05bc22d18ac2fa781',
                            '38daac220052b923debf',
                            '38fbc159afb3825d5b69',
                            '3904566e7a1d6d695f78',
                            '393e432ac309c3662ddf',
                            '3958a15c439600746180',
                            '395dc26e26c9289f53f9',
                            '39e693bd6d2e3d2c9b50',
                            '3a3d4254c9907289a944',
                            '3a73237a394de7d9e82a',
                            '3a8c6b0a6cf9d874e218',
                            '3a8d55da3e0c04ef68b1',
                            '3b19261d1af924e8a0f2',
                            '3b4489b5e5dd817c1e9e',
                            '3b4ca01a8ae89a7862f8',
                            '3b88a13b7a9c7adb7f3d',
                            '3c02c0e84877cc817b57',
                            '3c0c8dbe7191dc6f723c',
                            '3c13e2274efa0f45d756',
                            '3c34e0324e650b3a258f',
                            '3c4d8a37bc6105ab0764',
                            '3c5a138329682eb62dc9',
                            '3ced38c41f1e89560b5f',
                            '3d05028832b3b8aed4ed',
                            '3d09e2c4f65b2174b85c',
                            '3d645599a397bdac9fd8',
                            '3d6f39ee47ac580b83a8',
                            '3d92844774e38c1e2e33',
                            '3da2e224575f52b64fe7',
                            '3e41717bc19de8b7b904',
                            '3e974324986c8de212ac',
                            '3eb8bb3e70357afaca13',
                            '3f13648d0a3f21a4f948',
                            '3f18ab60f43503fcc852',
                            '3f24ff9ea3953c6a26bd',
                            '3f2679228db4038358e4',
                            '403193c060661f51a27d',
                            '40a0af1967e110842721',
                            '40bb691b6388c8355b82',
                            '410d7c5f34facc82c222',
                            '411b680019fe5c59a58a',
                            '412cbc9d20d4f11c0d14',
                            '415f0b7158e64c0ac35e',
                            '417b983244ca2a197a1a',
                            '423e237b5e64868d23eb',
                            '4277a0d1ff323f84a5e8',
                            '428460668d0041ae7c67',
                            '42fc8932d7900d889cbc',
                            '433bb9ae518bf7f2c12b',
                            '434dd1ec5061f582046a',
                            '435289cf30d372fb3bfa',
                            '4359fdffbadb47ed218b',
                            '4368438f18d1221dc019',
                            '437c1d5bf1cdd49d8013',
                            '4384a5c03144a0b2fd4c',
                            '438e52daceadc5d768bc',
                            '43cd964036fd670cf081',
                            '43f5452eb2b01150dc7a',
                            '4401297374e028f6b4f4',
                            '4423a239214ce9ddc4fa',
                            '44408ac5bf4601f71c92',
                            '44979b16d9b4fd62883c',
                            '44acbbc81d8ea8873052',
                            '44b0eb2ca39fef7769f7',
                            '44b6f6fe3fb2eb4ef11e',
                            '451b60bdca9c66e3fb43',
                            '45244c6c1c81752de093',
                            '4525c53a344838282349',
                            '454f1472f4aff4fd2fec',
                            '4551ed98d93d6510d870',
                            '45682b57d2f7e5878789',
                            '4570fd002222a1c5a8c7',
                            '4592dbc89002cafb7007',
                            '45a86d2201f3de6f3fd3',
                            '45b3fc6caab81a4f287a',
                            '45b85b9d38a14cd87ba2',
                            '46225bd14920e819b79e',
                            '4623567720c6fca0cdb9',
                            '4634e3560012d1641f0c',
                            '465f158b18662473c925',
                            '46dc9362bbd4d755288a',
                            '46f6e2996fa3064f3cdf',
                            '47121a5f392f34babfd8',
                            '4724d3565d8d1da3af65',
                            '472a4cf4a145134f8980',
                            '4747a9c78d6e53cac425',
                            '474baf09dc548b75ba97',
                            '476d8a1467aca7fc2b04',
                            '477882e0a7a87848fe93',
                            '478f03d2c3f8fa5cc0ad',
                            '47d666d251d282dcec2f',
                            '47f20b42415463d79ba1',
                            '4862d2c890bfc4d1d4f0',
                            '488f84bf3b4eed232b89',
                            '48ba045623e64df328fd',
                            '48df93672f3db104b6be',
                            '492044b38cdbc1c8f605',
                            '49579dfd153c10fa0d71',
                            '497b41949c845d80fa70',
                            '4982888f9f2556627a89',
                            '49aa53558b8a032711c6',
                            '49e0864a2ba0533b001b',
                            '49f127151985638646c0',
                            '49f420a59460d1ed277e',
                            '4a01cf9e602147038cee',
                            '4a68d3bc204a12a3d509',
                            '4a9f5a65ead26a46267c',
                            '4aaa17e68f487cb71310',
                            '4ab9bb27de3278af7ac1',
                            '4b1e3ae7419faba95cb4',
                            '4b39d5e609c4927c4561',
                            '4b527ceec01062825861',
                            '4b53e5596a9f23b3c629',
                            '4b7e51ca045a43cb630f',
                            '4b8b44228e3286ed187b',
                            '4bc46ae92382f250925f',
                            '4bc76322ee93127ea6ca',
                            '4c0cb9e62ed7951e8e97',
                            '4c208ef0f2f15b892509',
                            '4c4361a8f46d4d856d8a',
                            '4c4e9ee1d03b7dbc1759',
                            '4c52513fc2f9e98b520e',
                            '4c8d0c35d1c2b3a16bfb',
                            '4ce235d9c0f0a7e5893f',
                            '4d32b9dd8c64458b3003',
                            '4d5914430360470b2cd8',
                            '4d7f80bde30f09389d10',
                            '4d8575f09d9b1857af90',
                            '4d9da8d59cc660d2b480',
                            '4da15a4c67a5b936db0b',
                            '4da957918c279dff5dd9',
                            '4dc17b1d4876b6dda7c4',
                            '4dda51786afafc97cd1a',
                            '4e18ce39691d8f307fda',
                            '4e24e931e7a014d57626',
                            '4e4000d0c725fcb81783',
                            '4e7458dbaf15159b7c8d',
                            '4e8f63e1eabf4fb8e7a9',
                            '4e9df842e5f97010b9b4',
                            '4ef146d5633855caf0d4',
                            '4f043ab2e70cb9e32641',
                            '4f59e54596cd70ab1310',
                            '4f84fd97ac9a24a82efe',
                            '4fa39e7059d4e03fa271',
                            '4fc21e69f1e6ba5588ad',
                            '4fc2c8b8a86307a66fa3',
                            '501c2868f5fa02ce7645',
                            '5041ec13fd751ce83545',
                            '504bb4492cab51d2484f',
                            '5056c85bacb839d577f3',
                            '50be32bda4122e445302',
                            '50c6eb91e1ddf51bb9c2',
                            '50d4eda75ec3e6f71bb0',
                            '510d57d33ecdb75be7a6',
                            '511c0252b54c3c2138ab',
                            '511fec772735d0eb057f',
                            '5126dc2c42f99d3e53b2',
                            '51544213f5e83b082bba',
                            '519242dfa04adc27c3aa',
                            '51b89f843aa16a317c99',
                            '51cb4e78dd96da96540e',
                            '52103e17fa7959093c2d',
                            '525e3bb33658790b4d1d',
                            '526588962aed452afc46',
                            '5272233b489da201e52e',
                            '5276f2ac32aa28463b4c',
                            '52c260ea829e014adb40',
                            '52e9184ed0d8e39492d0',
                            '53060d4bec4542965b6d',
                            '533b8e9dbe5f150df64c',
                            '533e7df60f4c1b3467ba',
                            '5341af25822ed0141f52',
                            '538cbdac638a90c5cfad',
                            '5393512e8e88c90d92c2',
                            '53f6afd72822ccaba085',
                            '545a8a13ed43c74f26e5',
                            '54657989f0831d30f1d7',
                            '5468b89333b57b027386',
                            '5498a82f2568f1fc3108',
                            '549e3c8df4912fbec907',
                            '54be4efe9b452710693b',
                            '54dd3c76ec470efffde2',
                            '54efc320e0b7842e302f',
                            '55067c5d967108189ef7',
                            '552c6a0c83be4a84a3bb',
                            '55538c54b66224fd3a0e',
                            '5598c4f5bb329c22d72a',
                            '55a9787e1757bd7a3bd3',
                            '55bdd205b860f773bae1',
                            '55f9112e4e63cdbcca9a',
                            '560afd57042d57a7a8ba',
                            '562e65e139d93873a411',
                            '5648cf039caa7bb7e7cb',
                            '571c892cc96ad17700c6',
                            '572a71b8102a58861fd2',
                            '57499ab07581fe6ab181',
                            '5752bd4d0e6c46442a0b',
                            '57895900b838ca845048',
                            '579e8762251cbdbdc1e9',
                            '57bd79feef90e16b007d',
                            '57c64a1d9b6b98f2e9e0',
                            '57d608a2a83f2469d6e3',
                            '57d77824f66572ab4d2e',
                            '57e72738d31c2466734c',
                            '5834d8869bbd002048b9',
                            '583de354097eb7a569fc',
                            '58a8a7cd84f892ddfcf9',
                            '5908bed83c0abb0770d9',
                            '5929ac9d2b35e7d21a0d',
                            '5985f71f13431222d187',
                            '59908ce9fd9b4c500e6a',
                            '5a60b737c84994a4a2c4',
                            '5a8c37d1f9c56d3c5d6c',
                            '5a957959b0b20008dbcd',
                            '5aa9aeefe1429e05143a',
                            '5ac519bd805ce5fc8d59',
                            '5ac797e6f666e8f54788',
                            '5b32e29e8c53e8b38bfb',
                            '5b7b4a795ad7e6a4ff69',
                            '5b8798b313e7b210ab10',
                            '5bb8ccc206ca8e6fc1ed',
                            '5bee2b2c72c0b90fc46a',
                            '5c128e3b88b5a4a786cd',
                            '5c9e0a4f9914517202bb',
                            '5ccd5ba7112d2bffa9f2',
                            '5ce8740b54883fce14d7',
                            '5d33126385e7ce8ac6c8',
                            '5d545bf0805166da7c80',
                            '5dc28b6dc2fd1f96796a',
                            '5e13d6875041e3288912',
                            '5e2e9e75650fcb9d2780',
                            '5e5f8c086952d993850b',
                            '5ecc4253fad886c8ce64',
                            '5f37bda55c424647cf3d',
                            '5f4028fa4c1fe57ae21a',
                            '5f63c56a2107e17d7092',
                            '5f98b91479e1e19084bb',
                            '5fb6f74c6866b8e978fe',
                            '5fbc8505f1f87c1a421a',
                            '5fc667ed5b496e718487',
                            '5fcc7b2c97ff9e5dc12e',
                            '5fd62a62ae990573fbeb',
                            '601ee5b8301d9463b753',
                            '6066bef655dffc85950c',
                            '607414681fb28dfb50f4',
                            '60b05f8657789030468f',
                            '60f35ce41dcde43cb21c',
                            '612164251d1db021e911',
                            '61ea10c5cfa4368e8591',
                            '61eac973ef44047a559e',
                            '62064c31b471aeccd8e0',
                            '624924cbc9804875b9b8',
                            '6274dbf263e5e7f37211',
                            '628eca6c60ecb3ddb145',
                            '6299f021c5e0f7044ba2',
                            '62a158dcb94dc0294cd8',
                            '62a9d6ddba04655f68a9',
                            '62b327596865d5ec76b9',
                            '62b579e1f189df8fc83b',
                            '6341f77fc778fe88288b',
                            '638eb4bea0bdac699d98',
                            '639761df4b33a8743fea',
                            '63ff51f5b2ed3a9332cc',
                            '640e50b6895dc9168f70',
                            '644d6817c4c89537f429',
                            '6485e20d22fd1d419e7b',
                            '64fbf3aae6f93c1cd8f4',
                            '653cb824a27cb634a4e8',
                            '660a93ee38d632461f54',
                            '6669392bed9c8ea2315d',
                            '67257659a998728e5d3d',
                            '676bcaed3f66b8027fbf',
                            '67ae2f259bd80fabc0ec',
                            '6829bf15dda90aad3e16',
                            '6887ec2605c9f51bda20',
                            '68a35488cddb3546ab01',
                            '68a5346f0c1d451f3ea5',
                            '68c38c59a9c664646080',
                            '68f71d1adfff50284055',
                            '691d7b451c6909820e3c',
                            '693a66e7e4d430a86151',
                            '695d82b3585642e46d33',
                            '696ce2337b82abaf0fe5',
                            '69cf0e1fa51875d4cd8e',
                            '69f9a7bef3e1db1f8373',
                            '6a0e174beec5186cf51a',
                            '6a43e91a6cee243f53a6',
                            '6a7fe2fff0551f84a81c',
                            '6a805c408d7125644f40',
                            '6ad3a18c7442ad389da6',
                            '6aed01b8f106b751ea9a',
                            '6b2a85874ad506e882bd',
                            '6b656764b04f0394f835',
                            '6b86d68d03094e3dedfd',
                            '6b8e13262b6fad185dba',
                            '6b97e599932bba371ab6',
                            '6bddb67a7fa3178a2452',
                            '6bebd91a756d6b46a28f',
                            '6c318b0c3094e0b79727',
                            '6c41eebf86c64466d982',
                            '6cbe80a6299dd97e5c77',
                            '6d2ae6de1b7a03c0f721',
                            '6d7baf3de0b84b980be5',
                            '6da239460bad03641e94',
                            '6e36fce05144b97263c1',
                            '6e50eea2a951cac64f80',
                            '6e5fe0f06cabb491497d',
                            '6eb261ef53242304fca8',
                            '6ed8ce5a5f22c282157d',
                            '6f2d7ca08baa8140b207',
                            '6f5bc8ea06523f8297aa',
                            '6fa9d66db18e7e48291f',
                            '7003cccabcc2ad88d3e5',
                            '7020acb6e029fc8e0461',
                            '703094cd3384460cb517',
                            '70d10e58ee47f3d496b9',
                            '70fbfc663b138157422c',
                            '710eb13a51cf100d4417',
                            '71455f93bd7796fb848d',
                            '719b19960ee7f9952557',
                            '71a7aa5755f03d7724b6',
                            '721fd2e2222e9bfc0e44',
                            '723b27e5377f117aa780',
                            '7299bbbac0bf3486ee8f',
                            '72cb5ade8939d1a35b73',
                            '7314227c5bf4c5b121bf',
                            '7321f471c5c0e28e7521',
                            '734a5207df2d1cd0e5ae',
                            '7372d83a6fadc47cf2cc',
                            '73e654a3573bd8110ecd',
                            '73eb53c797163eac5e8a',
                            '73f910f1397ff3cd0d65',
                            '74e85eb8b8ea393aeab4',
                            '74f1d7d213440717a1fa',
                            '74f745cd3768687556b9',
                            '7550ea45e393069fb438',
                            '7564a7ca1bcf7412bdbc',
                            '75a1f2223c455c6d3be1',
                            '75d5e5827a9113867130',
                            '75f647709d453faddd12',
                            '7607d5b87ac145826b04',
                            '767d73ee7fa0a010eb7a',
                            '7697661a809c9f4e37c7',
                            '76c35fb86127a81be2dd',
                            '76cf099be652347601c6',
                            '775b75e4135e85037592',
                            '775fbae2ad40f7fa1c1c',
                            '7769415212ab2bbdea14',
                            '77824bc3ba953e05e7f9',
                            '77931a76ce4b93c35b1b',
                            '7798ffcb681f69a4809a',
                            '77a7fdd97037f847800c',
                            '77b40223a7cb3d8eb478',
                            '77c975bd01d6208de547',
                            '781205fc1613c6bfb41c',
                            '781895cc704cfcaf2c97',
                            '7850a29368463d94d78a',
                            '7859396588535bb96670',
                            '789216407761efa96e31',
                            '7894166a2c9014a22372',
                            '78950f813e33a5b27aef',
                            '78f498d6202b1a620eca',
                            '791252b10287cece9f8e',
                            '791710c2c46d8777a97c',
                            '79282c7973d3519a0476',
                            '79561581a60a241855d1',
                            '7963a6bea235ef3fceb4',
                            '7968e390283a0f72839f',
                            '79e613b65ee9d4114180',
                            '7a250d03ef28efbe826e',
                            '7a4c3926e9a7c076d4cb',
                            '7a80137fc54585e7f17c',
                            '7b132b6d0b197ac1ffc1',
                            '7b28e717d3a60329fd71',
                            '7b2fba47d55957afe1ff',
                            '7b47be4259d91045cc71',
                            '7bc72385c38b14ee8ad5',
                            '7c6ba4556b47fb683355',
                            '7ca26b005b13701afc10',
                            '7cb7e169b1057bfd8536',
                            '7ccf3841083042a0cae6',
                            '7cf14861414d52447175',
                            '7d4bc4cc35b2f2466288',
                            '7dc30ed79caa7c8ecdd8',
                            '7e9828fde42e6d2bed2e',
                            '7ee3f7c730dc016f7865',
                            '7f0257c40d75bc61a317',
                            '7f1eeb3a1b043d3a40ea',
                            '7f5c5e13ee30f8a0efe8',
                            '7f787e19ef2772bf4976',
                            '7f78f15d439a92a520b7',
                            '7fc44396b89f02802537',
                            '7fc9082d64eea47e12d6',
                            '8011c9631b7475c92365',
                            '8061592180f5293afdb0',
                            '807b4ee842ad13e99457',
                            '80955d08fe0bd7597737',
                            '80bd03e57adc95213f98',
                            '80fa19ec09143b884a9c',
                            '812604682df7fe4332b6',
                            '81390157ba4b73cb55de',
                            '8168d233732e6e06ee63',
                            '81a475653bf506a0cfc3',
                            '81aea6931c3bf3b7ead6',
                            '8209f6c74466ac83f5bb',
                            '824137a28e803d661e1a',
                            '827d764402c2452fc478',
                            '827e18d9e5078fe00114',
                            '82988b958b4979e25843',
                            '82ab89065f90f022fe21',
                            '837164edc422e097c332',
                            '83bca453c2bb662fe572',
                            '83d087f6ec05344a3455',
                            '83d6ee21fbc09afbbec4',
                            '83d7877798fb4fe5e499',
                            '83fe3312c4206ba83033',
                            '841a61943844b61b0b8c',
                            '842b384f8e6f6f7f9627',
                            '84e8dfd017a71b40dee3',
                            '85064720fbd53839d232',
                            '85480e32baba2e791de9',
                            '854c0e523d3493b677a0',
                            '8561cb9db9271537cf64',
                            '8588866d7150dd8b7c37',
                            '859f34ef8d14dc5ac9f9',
                            '85cb400dc0cae67ab2f3',
                            '8605ac39d09cb4d7a31f',
                            '86144ca018f9f680fe12',
                            '86c2a819bcf5391dbb0b',
                            '86f08194711bd83abf12',
                            '8830d7d80c2461bea122',
                            '88332ca4987a536dd3bb',
                            '88682a95e5ca73e76bcd',
                            '88a732141d3880b95bfe',
                            '8902023ce5ac67f8d6f4',
                            '8923e3eac04c0bac14fd',
                            '8961f4843d885b755d1c',
                            '898ddea4969d02af162d',
                            '89909848c5f1f72a784e',
                            '89acbad62e8be92c1c94',
                            '89b781c51669afed89fc',
                            '89ead30c9e34aefd3bad',
                            '8a066ad0c4576b226b19',
                            '8a4be1d2037bb67c096a',
                            '8aa181172c31b0d0cb51',
                            '8ac3e0fc3d45f0895703',
                            '8ac576e9f41020ffe51e',
                            '8ac71ecf4ae9418046ba',
                            '8ac7bf189ab9e42b181d',
                            '8ac9f18f5ac3d1345c88',
                            '8aec88f1c4bf5cdb52ef',
                            '8b1e8dbc5c139f8f3ceb',
                            '8b356b047490a701c616',
                            '8b3628f093a8052290ba',
                            '8b3b72d073c1cc9cbe27',
                            '8b3eccc05911124067c3',
                            '8b86c4736c8b7bc202fc',
                            '8b8e629b80f7718a74ee',
                            '8b91c5a7a13c5e0b0e39',
                            '8bb44e167d424735cd7c',
                            '8bba0efd6442eab95dad',
                            '8bf39bd388f48c60c441',
                            '8bfcbe54c60f2c2e10de',
                            '8c3b350a9c05f096fe89',
                            '8c64282527b78ac3dcb5',
                            '8c8999517c4b6b877341',
                            '8ca5881b4590d0f00cc3',
                            '8ca780323cd591d78dd6',
                            '8cfa1e464aa5706b6bbf',
                            '8cfc7490497922f1f74c',
                            '8d054af0f4acfbe28123',
                            '8d3795c4796d45f84b4d',
                            '8d74f07bb76e288ed120',
                            '8dbae43017c49f74212b',
                            '8df99813748840f7f35f',
                            '8dffac91a0dd96e98534',
                            '8e1ffc35d5a66936646e',
                            '8e4437ff1b049c3c6ea9',
                            '8e711a6bb900cfefb180',
                            '8ef759ba27375175b278',
                            '8f1a98d1cba2ac9c88f0',
                            '8f42fa0667e81b550aa8',
                            '8fbb23de872fbda860df',
                            '8fd8799386d244694b2a',
                            '8ff09d6f6600320d8398',
                            '904d2d7d758e6e05f53b',
                            '911952361f8c06be7418',
                            '913fca14eb3546d508f6',
                            '9152bf82b25be7c1addb',
                            '91f9814e6de390acd1eb',
                            '92827275767d7ddc8810',
                            '92d7eb0a3416614f21b5',
                            '92e30d8455a39b45d5b4',
                            '93194373a99f172439b9',
                            '93598bddea8289f85ae7',
                            '936b75c878a9efa60b4e',
                            '93a992891861e60ff2fa',
                            '93ba119d1309025756b2',
                            '9404f800a20d24d158b3',
                            '94433ca25adc74e393d3',
                            '94468ab722be4ec97105',
                            '9479bfbc640703045f04',
                            '94b1f9f1762de782c7ac',
                            '951c6081ccad6ac966d0',
                            '951c939a4fcd4472cb0f',
                            '9524f66b5b899222e807',
                            '95a94bb15fcef417d8fa',
                            '95b1b16fca932e3a0cac',
                            '95b8462a311e0234606c',
                            '95c26c610ea1e3a5f899',
                            '95e9e4823435680e34d9',
                            '964e95ea4639ae05a281',
                            '9692647b09664ecd6432',
                            '978853fb5d95a498ec98',
                            '97ab3ba0766eb2ace045',
                            '980e62e24cf721d8e6b3',
                            '982ca774af10659e7021',
                            '9838dfc9b280fe979220',
                            '985b8e832748abbba4ee',
                            '98852f64f2942037e46f',
                            '98dac7f90796a71efa96',
                            '98deff169b68b24e688b',
                            '99530df569c8c85a427c',
                            '9986ac98783f13752959',
                            '99a1ac45fc416ea65649',
                            '99b9b0afbd89d4f98295',
                            '99f7caebe31c7a2e22f4',
                            '9a202a0bf18dc2b20648',
                            '9a35ac68e982dc982b7a',
                            '9a3691275eabe92fdd0d',
                            '9a51e49227dc02e42e44',
                            '9a65f7e20bd3ea377751',
                            '9ab768670bb376c18101',
                            '9aeea1228cc351a9ce5f',
                            '9b47b5bb1168948d724f',
                            '9b6a8317aceb9b3e9046',
                            '9b98eccdf40c4cd12e6b',
                            '9bc60c8cb564fda28ddf',
                            '9bd9f3f2a1485605f2a4',
                            '9bdcf773d06864826bc5',
                            '9bdd0a3c512ab07e98db',
                            '9c263668bc2bbf2e5388',
                            '9c49095b40bfda80922e',
                            '9c683cd513f22b9a35fe',
                            '9c6e0e91c96bfb879592',
                            '9c8e22fa05f692c9c312',
                            '9c922847be3675a36d0b',
                            '9ca756aeb1210b1a256f',
                            '9cb4f4fd06d31d2065d6',
                            '9cd01bbe56b9f5cf9f6c',
                            '9cdd4eb5c20ed5f3949d',
                            '9d91513a592e5aab27c5',
                            '9da734399341ae2ee470',
                            '9da96da878ebd775a23b',
                            '9dcd801372d8c942abdd',
                            '9de2b076d5e0cbe4be29',
                            '9eb15ab9958f7b8ad995',
                            '9f0d83415198586f9ee9',
                            '9f4741eb9c9a0d61981f',
                            '9f739e5f3f871f98abb3',
                            '9f9a29907e736cf82bfb',
                            '9fd2e3d8ff9729c8e15f',
                            'a0313ac17dcc9b7a54e9',
                            'a047b85a96e94a104c89',
                            'a04cdbbf593d0f2e9663',
                            'a097b7756a6f22fb08bb',
                            'a0e7d8bad8f4f6b47c46',
                            'a0f713296b85fbbe32b6',
                            'a1431ba12c70861f6159',
                            'a160804a9c90a1ac6c50',
                            'a19cec50d93cf548966f',
                            'a1ce0768c1bbe9c3d85a',
                            'a2051f224e66cd783362',
                            'a217aed0777cda26e99e',
                            'a27117e6dfcbdf1aca8c',
                            'a2ddafc3d24cd74bd6cd',
                            'a31ac3cb6af9e813c3b4',
                            'a34b0ccfdaa0acad877f',
                            'a3b0e06324a84334bb19',
                            'a3c7dd8a1a6de212f561',
                            'a3dd564ac2c4d23a5682',
                            'a408b793ab15f27ae961',
                            'a41db302d41ced736e77',
                            'a42ea45f68ca6ef5d856',
                            'a4361e3f028ee5a3be52',
                            'a468a1c779213a2445e9',
                            'a47388566b13427e5147',
                            'a499fd0f12115dab9869',
                            'a49dfa6d36b0c9e3ca9a',
                            'a4a2929e55c5c82612f5',
                            'a4a56bc384aef6eb90a5',
                            'a4c1b849be747276a11a',
                            'a4d7df6d317d01baaa7d',
                            'a512981e2ec227bd0b02',
                            'a5292a1292aef5b50b20',
                            'a56fd0c7aa02aed2d2a6',
                            'a5a27f8a4812b3385364',
                            'a5a78b8048b32c678116',
                            'a5dd120120f5ec042347',
                            'a5efb04c54722c1f862c',
                            'a699d76d22333eb8745f',
                            'a6a18a277574aa057392',
                            'a6dae69af5421a017b3a',
                            'a6db4aa62c11e1c04aa0',
                            'a73b5e4da51566aaed4e',
                            'a75aca4ed704f948579c',
                            'a78b86c16d2aee04bd35',
                            'a7a5221610c15f61509b',
                            'a8047f52c6ed0e651042',
                            'a84f22094e8fda71e058',
                            'a862155fb3d68dd44413',
                            'a872d802922f1c8165c0',
                            'a87a24a3ff9e9b8bc28c',
                            'a8cbbad4359fa2c40027',
                            'a8dcb8749102d991d86f',
                            'a8e5c8d59f6981e7d629',
                            'a8fc3a79cb81cfa5f7cc',
                            'a91fdba5b387e7d1ee26',
                            'a9260340b44e7f042367',
                            'a93df18b95200abaa2f6',
                            'a940ace049a1768617b3',
                            'a958447b0f1d134b6667',
                            'a981abdd2751fe3e25ff',
                            'a98b092364ce63c40f81',
                            'a98d78357ff9c28c6f66',
                            'a9d8a36db5fd4c146672',
                            'aa7f5d0be75a6207a053',
                            'aaa86d3aba9d8f0ea698',
                            'ab03e6acd3d712fc2a7f',
                            'ab1cf3738cf32ec71680',
                            'ab77a54b82c003f79694',
                            'ab8db2081ff48aa0e25a',
                            'ab925fbfae85e4e7251c',
                            'aba948a055d698682844',
                            'ac4b7ef90f87261b5eaf',
                            'ac7ce722ea459190d03b',
                            'aca34308febb22235322',
                            'acfa166685b5daf37dfc',
                            'ad2c2e3937a203ad2a2c',
                            'ad65126b5fc1efa135dc',
                            'ae375b1c0d47499fa8d4',
                            'ae578ee517ddd6172871',
                            'ae629147005e59599f3e',
                            'ae874d8ff1988fd71b47',
                            'af0ff29966c820a2d520',
                            'af210f991dbd832592b3',
                            'af74a50fd49d520bfa17',
                            'affbab993ab5d2e5577c',
                            'b008f7f5b4bbe6e64303',
                            'b02902fe1a37c0f0840d',
                            'b038e9c4eed5b61844a3',
                            'b06abc8b3c347e1ffc80',
                            'b0b409b72a953c606e10',
                            'b120c40946721c457af2',
                            'b1271a656d4fb8e8018d',
                            'b127ef44683abf301d5f',
                            'b1481c9227e0d2f2c872',
                            'b1629cc19b1358b4ade3',
                            'b17998533aadd0305339',
                            'b1845e108fd7dbdcc73c',
                            'b186712c6ecf0cbfc657',
                            'b19b7ce6ba4d6def4a11',
                            'b1a0e1331441991ae221',
                            'b1c1060152ac882b5d7e',
                            'b21c79aaa859097030ca',
                            'b25151e7ab4de7be6647',
                            'b2a45bff1bb871ae95e0',
                            'b2b2d6513592171a8bce',
                            'b2ba7190ff4dc41f490e',
                            'b2c355c13cf4b01b0564',
                            'b2d0741a7c8df335a19e',
                            'b2e819fbff82c9353574',
                            'b2fd365f2eecd5dfa07a',
                            'b2ff787fd17ab396803d',
                            'b303057b53c98f592460',
                            'b30571d03023a518c076',
                            'b34221e19829b3acdabb',
                            'b366683a740e8f07774a',
                            'b3befea2289b25a0d79d',
                            'b3ebcb1de3f9b064dbad',
                            'b41140a55ca6098e793b',
                            'b423248b19862cd46636',
                            'b44fbeafead943221329',
                            'b488bd2050f7dc3b5978',
                            'b4a5c82f47996efce431',
                            'b4c33032f1f146a4c612',
                            'b4ed69fb7c7eb42d358d',
                            'b53470395a045699023a',
                            'b5588779956fad433535',
                            'b58a8c252c1bf3c02a43',
                            'b58f285bdd1d0f8bcedc',
                            'b5a342d90eaa779cbb1f',
                            'b5d17da3077259d03e06',
                            'b5d7fe469d8904d45395',
                            'b5ec1fbe1d0ba51b723b',
                            'b6272f588ba98625c2ac',
                            'b630f47cf174079317b4',
                            'b644fdebc44f1a25e645',
                            'b651400e71f3de812a52',
                            'b6a9195017ad95bc44ff',
                            'b6ee69bdcdb9d0fbaaf9',
                            'b73bf5ef403587651378',
                            'b7543122ce7e42a75e09',
                            'b771cc65b4680fd2c8c3',
                            'b777f462fa4f0a58dd43',
                            'b787f72fff8e1a713372',
                            'b799fbecdbdb0388bc6d',
                            'b7c3c7a632bbf46fc1d1',
                            'b824a80e611167143b3c',
                            'b89305cecd9ab37b7da6',
                            'b8a2c0016da6202f4b51',
                            'b8db854f90a9e77e7dd9',
                            'b8f42299c2590a0bce96',
                            'b90d4a25e4f288c07dd1',
                            'b91f5bdb0ec918619129',
                            'b92e7a58d64d96d1f8d8',
                            'b9afd2df834ac07a31d5',
                            'b9f0b5496a1b61a42ea0',
                            'ba19f7e3ea9e7b73ebde',
                            'ba4e636dc7b2923bf6b9',
                            'ba549438bea1388ed6e7',
                            'ba6a66d2d134ff0e687e',
                            'ba6e3180db09ae75857b',
                            'ba92828bb0a16c3b5849',
                            'bafba04d877af0c3e806',
                            'bb8dff4ad8e43cf0e9d0',
                            'bbe914d5c8673eb0a10e',
                            'bc7ad00969fde2fd94ae',
                            'bcbc3edad45892a59224',
                            'bcfd34cfc1ed1591df43',
                            'bd2d52e10f984090ba61',
                            'bd5b1bed50d9b80f3231',
                            'bd5e650858e7b80320e0',
                            'bdb1d1e7f506d06eea03',
                            'bdb40dc6d97afaf668e5',
                            'bdccb335c338bf5e4116',
                            'bdd3410520a57f3e7877',
                            'bddfb59ad8e9466f54c4',
                            'be7a5e81a0e0cc3891d7',
                            'be85120b24e51adddc54',
                            'be85928f8f66e734a716',
                            'be8875e6a895de11635a',
                            'bec0118f81fc6fc061e4',
                            'bf07caeb2c8a7d9c7f7f',
                            'bf46992853d3b77cd732',
                            'bf679e2e8f2bd3332750',
                            'bf71d5c98be5ae73884c',
                            'bf740a7bfc51f3b25a95',
                            'bf770f3f8f2e3a08ccce',
                            'bf7de1f04f25d576ea10',
                            'bfa34203f60157bb7f47',
                            'bfb10c75726257fe52f5',
                            'c00ace2031faa2135473',
                            'c00bee10d5035f51ccd0',
                            'c04daefc8427c96dcf5a',
                            'c0acac9490f31f48c23d',
                            'c0d2ab5a13ed6af2bd85',
                            'c0e1c434ac6372aedfbd',
                            'c10c43c0522c76e8e1b7',
                            'c1496d22f1276a8cb5b1',
                            'c15a4be158085732f355',
                            'c1ab40fe6b146af1d801',
                            'c1b94bd91920cb218094',
                            'c1c7b25e1d94ce090c5b',
                            'c1d24c6d134ecadb0787',
                            'c20980af2171acd9d37c',
                            'c22dc804fd84dcb7b64f',
                            'c2443135061bcd537903',
                            'c270ca1973ce31fa6cc4',
                            'c3775764e30c5a9e31a9',
                            'c3921e7ba20391896a0e',
                            'c3b93c661f308b5eb982',
                            'c3d36cad4346ce296b35',
                            'c4158f08c786122fcf2e',
                            'c44cec14558a838b68c3',
                            'c461662b685fe9702deb',
                            'c477044c6e28f6f36a3c',
                            'c4b434015c2376a711ae',
                            'c5115ce6194e2562e116',
                            'c55271a9352594057ac6',
                            'c5cbd7b0e5d518a477ae',
                            'c5e312bcb8c5b9adbbb5',
                            'c602f6750a4ea9c88e08',
                            'c61311f08fc78bb88f4e',
                            'c6240b692aeb392db534',
                            'c630fd6a338442be6dbd',
                            'c6c733b5b7ce6d489831',
                            'c7557774f923c3a7f743',
                            'c75c00c84599c47cfa68',
                            'c76bfa97e5d565d55e52',
                            'c7809001df36c42e1dd8',
                            'c78e7c7276750846be54',
                            'c7a53e4651feefc4f1ac',
                            'c7ddf8d6da9d4addae6a',
                            'c803fb77c18aed9928d5',
                            'c823f5306c35bd7f08b5',
                            'c82a4732e8599584e03c',
                            'c836d568691c2c388721',
                            'c88827398dbb784e51de',
                            'c88fec4bde0a225873fb',
                            'c8904543e2d54d1dc12d',
                            'c8987eb724ee01ec19c0',
                            'c8bbcd65b9c08f754c84',
                            'c8d5de121e946d5852ad',
                            'c922b2c6ce8468d1f1bc',
                            'c933813cc1630f129713',
                            'c956c5d288640dba0ff6',
                            'ca126af3c1348678f36a',
                            'ca53b5f7191a172200d7',
                            'ca6c8025bbdaa493ecb9',
                            'ca85d09f209e14406ced',
                            'ca87a454184766bb4da7',
                            'ca9f466c31667db1286e',
                            'cb0130efcca9e7a7e839',
                            'cb0a39c757a31b6cc8af',
                            'cb4dd8b9fd7c73ca6dca',
                            'cb53c22ef662286b7d8c',
                            'cb587a9efb4c65b6f043',
                            'cb5fac3fdd767409d782',
                            'cb6656f01013bf69fa40',
                            'cb8f9f748c6a61fc4779',
                            'cba07d9d77137ede5a8f',
                            'cbd6c9b815cd519da58e',
                            'cbf1ec47716502850255',
                            'cbf51d131bbbc4ecd510',
                            'cbfb500ffb22fa9bbb11',
                            'cc0603ec22cf168fb8b4',
                            'cc3536cb66f5c3c865cd',
                            'cc8845d0fa07bbd0c2f4',
                            'ccc1740df344b2f34daa',
                            'cd1098e5d3763eaebdfb',
                            'cd259f94285da4c275a4',
                            'cd4d1c542354d78bad2a',
                            'cda412e505a7cb908abe',
                            'cdd4811ee13589aa44bd',
                            'cdec3fba1a21430be4f9',
                            'ce194e5e806cc42758fc',
                            'ce1cbec14c512bccf21f',
                            'ce32eef94e05e4432c5b',
                            'ce77171cfb1206e198b4',
                            'ce95461108b5dc609c4f',
                            'cef0d479a46d526d8638',
                            'cf731084da08a30ae98a',
                            'cfc3a2ed8f3d036aad09',
                            'd02c24618bbe0e8d8910',
                            'd058cc329cad55f6200e',
                            'd0876a02ca0ec35ccc36',
                            'd0e19ad7f99e7a34b784',
                            'd275da9ba290b224d743',
                            'd2d0e5340348a8ea65b0',
                            'd2dda3c0b122f896444d',
                            'd3275e8bdab6bab58151',
                            'd3e00423243d03466082',
                            'd41a1ae267985a09b869',
                            'd4876ac85d5ce7604043',
                            'd4a405a7e07d2f5858e9',
                            'd4abea802f10a4390600',
                            'd4d8e1b23b36cdea5086',
                            'd5343c0587493172b1a0',
                            'd572bc72735f05310e77',
                            'd58cfb4ba25a63e38988',
                            'd5f16ead3fcec9b5bcd2',
                            'd6206b104471cc2524da',
                            'd66841e076c47727af13',
                            'd6d64ee868834ce65675',
                            'd6f3b226d6ace69feeb4',
                            'd710bb924123d4ab7ec9',
                            'd74a8b4240cd5b671e18',
                            'd7971e6479f9aec4bcea',
                            'd7c63f8c54fa4b197fd2',
                            'd8283feb42c99b69a867',
                            'd85967f271fda68197ec',
                            'd876242a799cc43c9429',
                            'd891ae0286bab8ab9857',
                            'd8e2a14ba0920c01571c',
                            'd9101f5f5b87c7df1539',
                            'd91884f609e0d15a38cf',
                            'd9253eee0fb84c8c9e6f',
                            'd935a47ba7c665e6a219',
                            'd96c516cc18c2eedf767',
                            'd980124be897797ca863',
                            'd9c3a44838a328d78214',
                            'da6227f8c0ccadb14074',
                            'da77e3660d0df816eb88',
                            'db30a5732120dc2c6d40',
                            'db582d0726680c5b29e1',
                            'db7e5bf7dbef16420a30',
                            'dbbaae84d4dea831e6bc',
                            'dc14b91ddba5be07cb83',
                            'dc7ab85ab8cd857a599b',
                            'dca8cc7d417be07bfd18',
                            'dce85615e9fdba65d10c',
                            'dd10fd7c313adc4c8210',
                            'dd2914f6b714febdf994',
                            'dd5783c1d39d221535fa',
                            'dd721456f10ded41a786',
                            'ddbbdaafcddb83dc654c',
                            'de3ec0cc692762f2ec26',
                            'de75b4f9e57855b36e32',
                            'de9b1768c4e14bb80118',
                            'dea6493e0c712e080f0e',
                            'deaf19e418a6b4590239',
                            'ded9df5be41d7d7ffa54',
                            'dee3d52fdeb0d278e888',
                            'df517703b129916a3cc0',
                            'df6ab1787cd1a417b448',
                            'df85c12023e7c1624b15',
                            'df885dbbc2b605e5b670',
                            'df9f76cd0c4fc9a50ce1',
                            'dfd54eb8e95d2bf1f3b5',
                            'dfe954681ab4008f5c21',
                            'e00e0fbcf7adcce2bc18',
                            'e041102ed33986bcb018',
                            'e04b2974db048db6a68e',
                            'e055696cd2648e623787',
                            'e0690e100a29d803a419',
                            'e0ff5ceeeb9e3db5f91f',
                            'e1024d82334cf3b5e9b7',
                            'e11ee377b1c3d831b6a7',
                            'e1488e338637c75a1e76',
                            'e229d41f3950eef3650a',
                            'e275c7a28541b0bd8b48',
                            'e2bb6f65c2d1f8828285',
                            'e2cd6347fc9a198c10d8',
                            'e2e6ac01ac7d304c220b',
                            'e34bbc2e8377d650b7f2',
                            'e3e11dc88518f9acc24a',
                            'e3ffa80b98303c45c0eb',
                            'e4462ccffeaae8a7ff00',
                            'e46034d919ac8bfd1b2e',
                            'e478966b29d010a8861b',
                            'e47ef746cd23b55575e2',
                            'e4bbe6d3ea516ee0ae87',
                            'e4d35fa89f125d0e4515',
                            'e4d5e1b19a945dc3e1de',
                            'e4d5f6a55d9661259477',
                            'e4d60bf671e30e3cb58f',
                            'e4f4d2b390dc66a87671',
                            'e5ecdd89c45d10db8fd4',
                            'e61d15da2502300a9578',
                            'e66ffe2dae0cf6eb9103',
                            'e6708ebb75a96170458d',
                            'e6c4c8f7cb64dbdc51e9',
                            'e7c4fab9afadec70d88f',
                            'e7e6fa795041abfc82c5',
                            'e7f7e4098947b7526eca',
                            'e82d521f5598dbd2ccf5',
                            'e84a9009eaf950f2a37e',
                            'e852ea69fcbfd7c3a393',
                            'e8706dac83fafda8c2ca',
                            'e893a9c45385133a28b3',
                            'e89437041fd3aa770638',
                            'e8a621d9c98934e4c9d8',
                            'e8ac00ef1ed1003c56fd',
                            'e8e1d8d4c3f5df5d008b',
                            'e96bd8be0acd758f553e',
                            'e989e027ec106c0a80fd',
                            'e996cadad4e85d5334b1',
                            'ea0ebc184ddf4d744dbd',
                            'ea41dd40a682e83d15cc',
                            'eb0396a8d52fdb084c77',
                            'eb14cdb868cf2fb9f4fd',
                            'eb35285f73dc26a55868',
                            'eb5a006bceacaa8b4eb1',
                            'eb703d77847a270223b7',
                            'eb9187bc70973b6d30a1',
                            'ec05816ece146518165c',
                            'ec0ff307c9267087da38',
                            'ec4396a6033df6f2610d',
                            'ec7dcbf15cbbe2315c74',
                            'ecc511b0a91fcc1b594b',
                            'ed42d517d8be7744754e',
                            'ed4ac756f7db3aa6273f',
                            'ed5a8f8c2be0f07666d0',
                            'ed6de1ac6d11a05aa92a',
                            'ed80c6aa251d129a8022',
                            'edc3c5712f34c6bea9ef',
                            'edc558896fb40f0f25ab',
                            'ede22cfe7aaa54720ddc',
                            'ede63ca7c86ff389a1b6',
                            'ee3c82e0c69d902f6aae',
                            'ee66b79bb08ab015d629',
                            'ee85337e3d64bb4aeaab',
                            'ee95e61cbf795af837bf',
                            'eebb62c6729ebb7c077d',
                            'ef43b18c1470aef5d66d',
                            'ef57a9bb0c28b9a83592',
                            'ef5d9b9d53653a2b6185',
                            'ef6e072938637859edd0',
                            'ef8d97f250630ca7e5f1',
                            'ef9505db1d3cedb69caf',
                            'efa0652ca3e32afc612f',
                            'efc6ae1885dddf6f859e',
                            'efd2fc56bc056b307ca8',
                            'f0025140dde5813a1017',
                            'f00f5a59e8bf95b9e1b6',
                            'f03d2aa4d434a703a1f4',
                            'f0517b75251e036de54d',
                            'f089132a6c1166068e4e',
                            'f0ba77863e6998ab89f5',
                            'f0dc76f4442dba040e9f',
                            'f0dc7a286a30c3a02286',
                            'f0e2a081849a9eb27c27',
                            'f119854cff642abf28f0',
                            'f12b6b36cedc8a2c1ee3',
                            'f160ff3f3de0c0fed909',
                            'f187f64e2dfe44d2c75c',
                            'f1ba02408fdf3bac1aa1',
                            'f1d22be18e2b4f2b1017',
                            'f1d71bfaa723206ab49f',
                            'f1e277596525a0487eae',
                            'f25f23f324ae8bcf52fd',
                            'f2680c16584115fb4ae2',
                            'f29377874ef1d7fba0bc',
                            'f30aab70c8c0708f8aa8',
                            'f328474a11941c025338',
                            'f3914a55d7f71f6ba297',
                            'f3a8b8c6dc0f2c820e31',
                            'f3bc4c4da3159fc4c4b3',
                            'f408af3e13e34b1eccc5',
                            'f436c257dc9ddf822c9a',
                            'f44cf10022a6d1a024ba',
                            'f44f700652d827519c70',
                            'f47f8553d7a4812c7a8e',
                            'f4ca4d5b869c1e8d9d79',
                            'f5525ff6f2ba97eb6b05',
                            'f559bd7389004a57d981',
                            'f5946c6d76f7e91294a7',
                            'f599790e24508fab03ca',
                            'f5a0311190289983b4cf',
                            'f5ae88ce435ccf65087b',
                            'f5b7b026df21267bf41e',
                            'f5d4e81c18f3533042b4',
                            'f676bdcec097de36d4a5',
                            'f6ccf87ed5cb650cf592',
                            'f6fb3f9a3827d3e3e307',
                            'f6fea226a0f1f2bca804',
                            'f71d1110a401088406ef',
                            'f73b656fc67a9056131d',
                            'f73ccdf522b6baaba0d6',
                            'f740a4a664c4e0964005',
                            'f75ac229e4233d9a1315',
                            'f7d37aee5c0e441cc1ac',
                            'f80b7878c4e922632b0d',
                            'f84439bb09b90b0ab7eb',
                            'f84a9b451b61e454b314',
                            'f86e7a8b29706ff9e8c2',
                            'f88597a1e6060e8cdc4b',
                            'f9035cdef2bf58687fcd',
                            'f90510c59da8f6e2d1b5',
                            'f9138fc3a2ed812402e8',
                            'f9c42f9e8061592efcde',
                            'f9e75e7c28fbfab4e1e9',
                            'f9f48077104bf33d2ef3',
                            'fa29802e52fe9f5386c3',
                            'fa3296e955886f3d8ed5',
                            'fa8eb2cb5792f466ac5c',
                            'fa955be8bff4bd6c4fe6',
                            'fab2e987699756088e54',
                            'fab7f5dee9f1acc5b6b5',
                            'fb0b108c492ab92ee864',
                            'fb1c0de80f28b254a3bd',
                            'fb1c1ebd7d7ed9eb3425',
                            'fb295c28f037b2ab1e16',
                            'fb36eff08d70233d27a4',
                            'fb3b08b02e92464c9078',
                            'fb3b86c079ad07c4268c',
                            'fb5f4518a17d4b245484',
                            'fba07638973147e41e42',
                            'fc00d0981d6d49063e66',
                            'fc59274bf52c3825d631',
                            'fc764f075b2f0cae8910',
                            'fc798999fb9aba995c94',
                            'fca0ad24cecbb6528f93',
                            'fccd0bb376cbe0d44788',
                            'fce98b7658a08b48a427',
                            'fcfe4e6fbb7ad45c28c6',
                            'fd00f45e56305cd3b428',
                            'fd426da6ede374b1777b',
                            'fd7980e222a322a1cd57',
                            'fda1c2d6994f944f9063',
                            'fdb089588e6bb1941a16',
                            'fdc47e05b1e884bba362',
                            'fe3da68d42a94d34ac61',
                            'fe467c32611a06beb5dd',
                            'ff00df50494bc8d7822a',
                            'ff05a7044fbee2a397d4',
                            'ff07d98602a1955f88df',
                            'ff0ce225fd172565e917',
                            'ff36aec02bc7bcd0290f',
                            'ff658c5c20df1f18b99e',
                            'ff7b3c2c27769e589e41',
                            'ff9b75722a3b12ae37c0',
                            'ffcabd1ebc6436a18fa2'],
 'private_history': ['902f9dddc1814834a088', 'ebb493248a75bff5a388'],
 'raw_decoder': ['07a1f380c044fdeb17b5',
                 '09d7d40a094d224c8bbb',
                 '0bb288f3a6db027a3a31',
                 '0c33448cb40a81de7804',
                 '0efebba4cc944666e05b',
                 '124c06366fd839438d84',
                 '189a6999f48d9317db35',
                 '1939efd6562cce53d350',
                 '1d1f6719e4a49360a56c',
                 '1e545dbc3e62030811b8',
                 '1f3fb30eb9f5820be82a',
                 '2043b9ce3aa9c4f2a908',
                 '22031720aa6cb836fd3a',
                 '225e76b1ee5bd26f622f',
                 '234e449220da93456d3f',
                 '24584b59efabbed8d06b',
                 '2c47da67021fabbdaf38',
                 '2cd2950000b1a8527832',
                 '3a62f8de4715a8c90ec3',
                 '3a66675a4b0011ee03b6',
                 '3afc29f53e84d4383b33',
                 '3cec4b9561c39db0021d',
                 '3e4dd112ecec873de5ec',
                 '4390e8f7777eaeb1caca',
                 '49b7bab0842b60096b88',
                 '509f9e923fd76a33fb65',
                 '51f540d2f80dc2bb7dd0',
                 '53fcdc2614b2aa36e403',
                 '5491796774dbdb237968',
                 '56e4af627aab7de0d10c',
                 '571ddcd48b4b11f00301',
                 '597961666f27eeb4988a',
                 '5a5c92628f823c188829',
                 '66f4343377dc62a26c97',
                 '67964198745de0eb8e58',
                 '688b78b72fb276c2f4f8',
                 '69eeed27c50c8c6772fa',
                 '6b9e9940d1e1fa5bf2f1',
                 '71bb889ec63fc3e311f9',
                 '739f9adf46a5d565073c',
                 '781117549350885c9d80',
                 '7c79a2464ad7e2a23b9d',
                 '7c8413179d7530c7bf8e',
                 '7d6eb2a7c812429a96de',
                 '7e0ff9fbbff88a904d2f',
                 '7fdf4544135b8deff771',
                 '804fbbd3354ab9282180',
                 '827d8c0bddd615109af9',
                 '847bb4c9fbb9f72e0f93',
                 '84aa9c10696fff6d6bb3',
                 '8525eaa367c5c0cf2202',
                 '85b4eb124cfd28960a79',
                 '870adbefae847d10a283',
                 '8c00b776726bd4bdf54f',
                 '8dd61744be5e6267794f',
                 '8e2078f4c9c9b1035909',
                 '901b2a7e21289ab0a39f',
                 '9343cf5dd2d480b02420',
                 '93fbda6327438e082503',
                 '9dc1aa52220e7db9d5a1',
                 'a0b1310abb47ded15f91',
                 'a16697cce6efffa332f4',
                 'a1fc375b3c0a06dab23e',
                 'a5775e95d475aa7b7103',
                 'a57ce0d998910ed6abef',
                 'a6230aee9837e53b35e8',
                 'a6d23fca2444de41f23b',
                 'a89bcb0a61471ca748a4',
                 'ab33bfbbc25a298bb9e1',
                 'ab3de4c282d639fb5573',
                 'ac78bc43d29b33cd94d5',
                 'b356765b0d5220d3d730',
                 'b673f92ff769fafafef7',
                 'b8e39bda87dc7c003979',
                 'b9723311713a532f79b7',
                 'b9a91f48762118eee430',
                 'bf917533f8f4345b73ed',
                 'c1e870834f1bd511c938',
                 'c207e3d7f918c6e1ffd9',
                 'c280ec76928712052eb3',
                 'c4383a3929d8ce128cbf',
                 'c7a7993dd7006f165788',
                 'ce01507c028226b67c13',
                 'cfffea519196e2a44f24',
                 'd7736c06abdd2f3b9fa1',
                 'd9ead1dd79908bbd1b2c',
                 'da2f6e5963b31fcd55a8',
                 'da63da5e218b81640d1e',
                 'dc5029f795ead016a3f4',
                 'dcbdd80b1dce3ec2486b',
                 'de39e0007d0d0809164a',
                 'e6cc283cc54e76a52620',
                 'ef5866d1a74b4b912a2b',
                 'f17de4bb1914cd2546c5',
                 'f3ca0132095aaa2dde70',
                 'f5a7e568f1a448964c41',
                 'f7e9a82d605e1853bb2d',
                 'f8c16e9b12c4f255a490'],
 'transient_or_fault': ['00f6fe0246129fec4f86',
                        '0178ecebcc7495270422',
                        '03fc9ad186e0594df413',
                        '0965a66d57aa5b6b60a9',
                        '0b5dd975e8ecc8b356d4',
                        '0caa000087c3a780d928',
                        '0dca23ecaf2e42ee2cd4',
                        '0e062b9e17b175f36c3f',
                        '103411cb2f91d87e1fb9',
                        '10f7e2b9f2ae49c4473d',
                        '1110e83c123f5890ccf5',
                        '1388118186da99177781',
                        '17316afdcd85e510dc37',
                        '19ab6a901b0d4037a6e4',
                        '1a066193ac364d1461e7',
                        '1a327eccc72d8558a55a',
                        '1abc61ea2fb5b0209704',
                        '1e61feaf1426bbe25d90',
                        '210b1a93e01950fbdc92',
                        '22ad8a2d610d35364af5',
                        '23598c880c9c508a0e0b',
                        '25edcf7c5ab03e107d1b',
                        '2717a1d0f3551ba3b9dc',
                        '2765dc4363647bacc8ea',
                        '27cf8b1368dd2627847a',
                        '281d32132e8382fe6b81',
                        '285018779f2c75d0e8fa',
                        '2a8e3e567b257de7e158',
                        '2db6d5dfd0758315aedd',
                        '2e954fa6ccf7b2cc780b',
                        '32f8075e0f143c652c2b',
                        '3594b85275efc24e8205',
                        '39ed6d45cc8aff2f681c',
                        '3b0b2fc846f4472a2dbc',
                        '3dd64ae5a61711649f20',
                        '3deec8939338a81cdeaa',
                        '3e5174715126a5f7b05b',
                        '41a69b118e6087c4db70',
                        '45b13a5f7591b07be16c',
                        '472d9bc0465ddd237c2b',
                        '474ad76ea898a2703ad2',
                        '48204c7fd246e5515100',
                        '4987366f61d7e90b36fb',
                        '51e7ca0caf485135b90f',
                        '52c7accce7eeebbd0876',
                        '55139821c559f3732912',
                        '553319e7b843e958a467',
                        '5681c11ff32f09e88bad',
                        '57329d94d6701351b4a4',
                        '5968aac555a129edb92f',
                        '5e22a752c1e35af76f57',
                        '5eb785eddebc35cd56e6',
                        '6107a46bcb3eadb01d4d',
                        '6131d63c7205f9adf882',
                        '623b673d58385b6c05df',
                        '62859c75768ec85e9d93',
                        '658a4f8d49017194334e',
                        '673c211e98920907e2d7',
                        '68c319269d37f0852801',
                        '6a184500987f2e71bd1e',
                        '6bb5c22f2b41765770a1',
                        '6eb126326b5c32d14bd8',
                        '70c86f1b8bc1bfe6cdb5',
                        '70cee544b6acbc659db4',
                        '7101dba1dde3d73344a3',
                        '75064289a44b15c75181',
                        '75985ca824e8c378b632',
                        '79794238bb36829fcf02',
                        '7fffdc4a3f40836e2e53',
                        '810f8201a7119f2fbddc',
                        '8aa6880f4b64756db21d',
                        '8cb67792b8da8bcb029a',
                        '8ffddcc041c4702a06b3',
                        '91d01001370b045d3587',
                        '92ecd6dac8b888e88a63',
                        '92f84855ea2c4b5ca41b',
                        '98801de3b6288f2c8280',
                        '9a433d2430640e5160fa',
                        '9a87b6d6f95f532afc44',
                        '9b63854d0c697420302b',
                        '9c1dd6edfbcdee5e91da',
                        '9c3c7f970e33a7ee853f',
                        '9d3a46d7502056b497e0',
                        '9da2a2cb9b3e9ab9a3c1',
                        'a093b3b3fe1819e4e7f8',
                        'a727fb79295724a762b4',
                        'a8455866e637af78b850',
                        'a87df5ef76639f18f4f7',
                        'ae48c69bd2f1d65e2ce1',
                        'b2790afb31d6ea8ca651',
                        'b32049939241b3cd98c6',
                        'b8365eefac14b3d1482e',
                        'be5c4ea4565986205864',
                        'c2a0e3b20be671b03134',
                        'c9e0c7481090dc382453',
                        'cbb7306740665d86393f',
                        'cca5333fe7fcaaeff857',
                        'ccf2cbcae2fca2a85467',
                        'ce1636eee54e30c8cc6e',
                        'd258d40eebfe112dcd67',
                        'd3cc60185ba243ccca73',
                        'd3fa8cd53dd12cd7b81b',
                        'd457a44032619ab75742',
                        'd5e0c295b8873b523894',
                        'defb9ecbe606f5cca521',
                        'e26bd345a0998160877a',
                        'e3ac8618c4833ce522c5',
                        'e5dcf3fe073b06292787',
                        'e726bd19c7b1c32e4aae',
                        'e94f916b8d2fb884aac9',
                        'e9ad736523dc07ae3c19',
                        'eb140b5cfe704a0b8e06',
                        'ec29c35777f7b3a372f5',
                        'ed92e267245d03f246d8',
                        'f33534b2f062ea7813f6',
                        'f3d1803fd8740fb3aaa4',
                        'f61b77d1e1580a421d7b',
                        'f7ab787edd886981bf25',
                        'fed29c9f8dee576d4c2b'],
 'unexported_module_state': ['002cfd0405ce2bbac574',
                             '0083ea8a5b686d5fc9ed',
                             '00999528a2fe4d865b6c',
                             '00adcdc06fb499b70ff6',
                             '017c8826fe4d6785d182',
                             '01d44fb12d74e04dc737',
                             '02538263ccfc708893a9',
                             '028c83740de7c09c9c3e',
                             '02cce4fa6b648adb641d',
                             '03868eab579f855dad87',
                             '03b66de76b47b3e3ad50',
                             '0449ad3a2124d41fd699',
                             '04f1dd99d8af00136be2',
                             '0559413e59ab45193c6e',
                             '05666db3896ea2946221',
                             '059342fb63cc07494c8f',
                             '05fbfd089692714ff92a',
                             '0625f1c17981a56006c5',
                             '06d4f9b548e8f3d0cd8b',
                             '06e562f219a91068cdcf',
                             '0709ac73c69796573ed2',
                             '0748982494ce1b4a136e',
                             '0757c8ed43ebdda1d373',
                             '078b10efda0c0308a974',
                             '08c96c7a81486f1b60e5',
                             '0923b7c4e0598a239814',
                             '09a3efbfca017270d626',
                             '09f80a0d1032fb62c5f1',
                             '0a8834c52f3460955e27',
                             '0b229e93890ad89cfb08',
                             '0b8d6af9576a30163ce6',
                             '0bc51c27e92d5691cc1e',
                             '0be51c7d985f0f932889',
                             '0c3fde5c62309f73f1ad',
                             '0c4d36d74695c354cd0e',
                             '0c7686c55a9bfab0c104',
                             '0cf6e07b97063b17dfec',
                             '0d2fff96ef2868342b7a',
                             '0df2fe2026c554c6d767',
                             '0e64a18a08620b4928fa',
                             '0e7cb284681bae3c76d6',
                             '0f3ad66ec11ba0058db6',
                             '10643a2ff16da30d1637',
                             '115f4443324594dbf2fc',
                             '11c6430c1a06b72ddbd2',
                             '122d02b4297f3cf721e6',
                             '1252b347702e37fb55eb',
                             '129c6e3f5081ca5e5b24',
                             '12d8238424efb97a34f9',
                             '130be606e102ee386923',
                             '130dd549ef19bf36889b',
                             '136227ee8ca460822e67',
                             '13f92115a6496b6f48ed',
                             '143c860d45a9a930082b',
                             '1472dacffb942b819a5a',
                             '1509757c6086f5c5c127',
                             '1518c04e96bb05214ea7',
                             '151fff5572c5b6dd7689',
                             '15310633fd1299b0d6c8',
                             '1544c3321e91ef436893',
                             '15cdf4e5d45409a45ff8',
                             '1640a85b6bcabfc5204a',
                             '166484f44fda56a6cca8',
                             '16ae3224eb055774baf0',
                             '16d4f0ed4d0edc7131fb',
                             '186634de017ef79d203a',
                             '18673b314b00271ccd22',
                             '18ae1313baab2c4cbe26',
                             '1921bc100f95346caee3',
                             '195aff434afe12ef6258',
                             '199005293daf88f4afc9',
                             '19967815e9c5604514a3',
                             '19f280d2c808874e7798',
                             '19faa9ed12dadfaaa6e1',
                             '1a1ea261baa6fd58b26c',
                             '1a32065c5d372c9a92b8',
                             '1a5d98409ccc46f2952a',
                             '1aae1e5abcd7e6e1989a',
                             '1bdef8aaa76c08455311',
                             '1c29de8028d954cfe4f4',
                             '1ca8896104cf2630b8d0',
                             '1d19f63a20013ad80093',
                             '1d324d4186d3446966c4',
                             '1d5ab680b0ba370349ef',
                             '1d8212913306c4967028',
                             '1d91690e9808d7e5a420',
                             '1d93d9057dc57c4dd386',
                             '1ea487ffceb62c74291f',
                             '1ece872be2e8c274f839',
                             '1f046c381778663db59b',
                             '1f25aa457bcf04e169c8',
                             '1f8e52ce34f2e01e8f2a',
                             '1fba4304406fee273e7c',
                             '1ffd83c020bb4127586c',
                             '2018a01ef70de7b6fd98',
                             '207b8b3491852c30a817',
                             '20eb0877f6acdb0c7af2',
                             '210f992feaf547366d71',
                             '216de3c091c345d55d85',
                             '22502ce272524200e4a8',
                             '226a7945095f5e2610db',
                             '22717518726801eba052',
                             '228d2d88b959d39152d9',
                             '229b7988b86ca164a84c',
                             '22cd64db47082a805348',
                             '235bd70fc6a62d760651',
                             '23853b0f7f09234ba33e',
                             '2399fae794108cd6f529',
                             '23fea98aee1587af3dd3',
                             '247932091395ca0b4b47',
                             '2483818ac843ec752649',
                             '24aaf34b16e3f1923a75',
                             '24e56000a74c5aabebc1',
                             '25183ca4d3b0bad21002',
                             '254d3c4de8fa94c8beaf',
                             '26123f126011dd2ed8f4',
                             '2624854bf5d27b0138de',
                             '2797fa8f4c87e0d0e395',
                             '27bf05765b97ba79649a',
                             '27cf1bd13d50b652443d',
                             '283282ce34210e032924',
                             '28447400ee349a80954a',
                             '286b50692d0f19c8e7a6',
                             '29255111f6cd19b36d87',
                             '29ef9adebbf120eb80d2',
                             '2a0047af3fbe33ea9243',
                             '2a2f1e972a756f370840',
                             '2a6a3a52c611af5956e9',
                             '2abc39ff0a4833e19aca',
                             '2bd5cbefe24666e70092',
                             '2be4913d974006b9e31a',
                             '2bfcd99734e662160c3e',
                             '2c05e63fa3e8161bd190',
                             '2c75348722263a1ba8b8',
                             '2ce939af9baf07562b97',
                             '2cf46b025a0af7afa4cc',
                             '2d04ec57af4c2bfdf9d1',
                             '2d2d3d32d65a02adde38',
                             '2d34b0ce82f947e04862',
                             '2d432fddd345a016ef58',
                             '2d7b7b024edf0963f94e',
                             '2da34c73239c400d37d7',
                             '2e2e8c65fc07ed9dc396',
                             '2e4a50aed3bb286d7df0',
                             '2e9bac1bd03acf75f151',
                             '2eae42c63dddd6deb40a',
                             '2ec47dc93e7b90072bbf',
                             '2eda330b62ff8ff7e779',
                             '2edb3dc4731c703d30ed',
                             '2ee4d135cc5d2b2db1ae',
                             '2f062bb31c7050fc065e',
                             '2f0d75d5c7c8fcbb69ea',
                             '2f306f7b7fd38050c351',
                             '2fe71399653c6d87f55d',
                             '2ff5a916d68d888dc46d',
                             '3020b51c3eb0cf510f91',
                             '309c7f6682f2557291da',
                             '30b5e036a6975ad48a3b',
                             '30ddcc0f6ff8c39df390',
                             '314dcf1bd03deca2e565',
                             '31ad504f18bb14c81b5a',
                             '325c65ae91d70d4b09e0',
                             '3275835f322eef0d87cf',
                             '330a705ed10f63ff0deb',
                             '33d6a31817e7b2ebd58f',
                             '3466ac06faaea07cd85c',
                             '34e8f4f1bf1d86bd2ddd',
                             '350189c6535700ed4fe5',
                             '361cba2921972f959d3e',
                             '376f36cdade1481aa74c',
                             '38d486db470ccc71332a',
                             '38deabdf817c6aed055a',
                             '392c28ddd5d53a9a69e0',
                             '399ee212040f7c36a72e',
                             '39e2c40058774ddebc2e',
                             '39ff972a6e9702e2a253',
                             '3a939760b98ebfb3a395',
                             '3ab1990cd6a063c8dee3',
                             '3ad79f5f3279645e2d2b',
                             '3b19935126ef6129cc8e',
                             '3b1e911ad566ec21bd00',
                             '3b55f129b369ede0afdc',
                             '3b87b380caf31821c770',
                             '3bcfef4e0bb0afd8a677',
                             '3c13141971ea2d93be7c',
                             '3c5934b5f5d3ee28569b',
                             '3c77d44d41057a8f3746',
                             '3d25c338e855b405bb45',
                             '3d294e33ae1797859f94',
                             '3f8870471c6ef998a475',
                             '3fbc562725b4ee749016',
                             '3fddd491103a9e7261b6',
                             '40078ff39103f915ac16',
                             '40adf5ea003311915e7c',
                             '40fcea7cca4959e6151a',
                             '4188a4508acfd0e090eb',
                             '41a922c569b8214fc0c0',
                             '41f1ad5392e90ea23694',
                             '4206bbece6edc03b077c',
                             '4239babfd6af25d18050',
                             '4249c425b638b9384623',
                             '4271ee102126822e128b',
                             '429f12b60e4fbb96869b',
                             '4363bdb1bae97ad64c28',
                             '438d5b93d8520ab53a9f',
                             '43a06516e5ae7a00e00d',
                             '43b5253bf61622a193bb',
                             '43b7b04164c26501fc00',
                             '444a40169cb61058a677',
                             '4473c346ca187e8e303e',
                             '4490bf57e6130e99c1cb',
                             '449d5ef0d0294d1c2d57',
                             '44b0d7aa6802af0bdf0e',
                             '4508c5eafd663a631d0c',
                             '457aa43a0349eda9b20a',
                             '45c749956f7f033a1ca2',
                             '45e5bb7327cf6f324747',
                             '45f5163ff63b797eb2d5',
                             '46d214267b93744b6b00',
                             '46eb693094c33494eddb',
                             '478a167f32580e0c13fc',
                             '47fe9b5c652ca152f460',
                             '4848f627c7a2e456c315',
                             '48947817336fa3256484',
                             '48edf891be91741fe077',
                             '4912373078f5a2926a23',
                             '497978ad794b8ebeeaf2',
                             '499de896dec0b070ee8a',
                             '49c999e705f23624109e',
                             '49d666dbeabec3a319a3',
                             '4b9503a220e75be06d93',
                             '4bb53704f523b892b65f',
                             '4c604444549d21855d7c',
                             '4c9db4d6b89a3aa08f92',
                             '4d3881d62db65f555c26',
                             '4db8bbe593b6e61e45f4',
                             '4e39ab09c2d84a757921',
                             '4ec89d1e80cc58092e25',
                             '4f21b6cf3de066844254',
                             '4f2d473f081caeb936cc',
                             '4f2d4c18a57f23b76cab',
                             '4f3e5555875ac39d2ae9',
                             '4f7d45339787c899ec85',
                             '4fa45443822a74eb674c',
                             '5003a8d40a3dce5fb47e',
                             '500a0059d3f5a012b286',
                             '50a8f42c19ac5af53478',
                             '50c8b6e4570cad53c272',
                             '514d0bc84c14247d31ef',
                             '51d1b4689aa0cf145d26',
                             '51ff0aa6581a3004989b',
                             '5201397e335ff1112ee6',
                             '5209b49e7f688aae0f9f',
                             '525fb015fd21744d571c',
                             '52f6a63622c985d81b29',
                             '5328f9cce4359d10ddeb',
                             '534a58dc550aa986bec8',
                             '53d45aa4e92f4e90dd2c',
                             '53e1021d6cf403e917c8',
                             '5406d173c1a0cbfa153d',
                             '542264e11d8c09b1b4d4',
                             '54dddeeb5ffa79205018',
                             '551a85b7808d639a2f54',
                             '551def4fc3868c0a34a5',
                             '5551f2bdea293c65a15a',
                             '55b5bd5cccbbcd1d7deb',
                             '55eb26ee9f167d737562',
                             '5606e74ba53c2eaa3f89',
                             '56139f4d2edca4f78a0a',
                             '5637ab2dd4065991d3a7',
                             '56a2e0e62045361053c2',
                             '572d261415aae3456f2b',
                             '574278766f8ad452bb28',
                             '576b7488e43ad54cc061',
                             '5772fed1a548a3a06fce',
                             '5882ad0c04d7106dd37d',
                             '58a67a7fa6fc427b9776',
                             '59497095d482a322af2d',
                             '595810142c45cc780d2f',
                             '59e9aed61217ea1cc58f',
                             '5a0be2b56025103a862c',
                             '5a0f168fb02bc11e1a58',
                             '5a1e356eebe4cebcf126',
                             '5a8034e1950b91c912dc',
                             '5af9e9d1cdc09cada06f',
                             '5b6a35cddff38ddf342a',
                             '5b79334e7b78250692cf',
                             '5cc478c10001ca2a19d7',
                             '5d2864351491b5221ce3',
                             '5e2c45042738930cd3b5',
                             '5e43c75b5709b53ee167',
                             '5e53a5d7e6a3cbe046be',
                             '5e89aa05958e92bb9882',
                             '5f245e35ddaeab09e7ac',
                             '5f60986c0d37b66f633a',
                             '5f700399c0adab477e09',
                             '5f7ad8ddf901cf3acd5c',
                             '5f7ed416091d7bd7c035',
                             '5fdc17b49d5f7b69cb37',
                             '603bc86e2408661b4296',
                             '604e1f75fced6b9877dd',
                             '60cc34d174a3e5431d9c',
                             '60cf9c3c82d5ec45ab3f',
                             '60dcc197fba267fa46a8',
                             '6156273e2a487db139c8',
                             '61803333413403857030',
                             '61a6674c187d3a1cdc6d',
                             '61a75e4e66425f7617b4',
                             '6264688721b87135d2df',
                             '63809e7ba1dc7c16233f',
                             '63efc10ff05451a1e5a3',
                             '6416c160174e5d5ecb84',
                             '64341b7f2b896a3c42db',
                             '648704955beeb1996723',
                             '649f154deef52d58f3d4',
                             '64b06adba612e1d5ef75',
                             '64f6a8c3bd929c7ddc9b',
                             '6555985f3f8702b800ec',
                             '6563b67fa268b8dc0d79',
                             '6593970032bf15202dcf',
                             '6606a3cc9876995ba64d',
                             '6607c48b383e123675f2',
                             '663bb060f0c62568745a',
                             '66572729b936c3d528f0',
                             '6661cca8ef309d9964c5',
                             '667ea15a109e42360057',
                             '669a5a79aa61c524c8d0',
                             '66a87e87c89b79e42055',
                             '6701becf54b0b222694c',
                             '670f564a7998b5a4dd0b',
                             '67d0125ade47c58ab11a',
                             '6809ec97204d6a50effa',
                             '684e631aa0e6250481ff',
                             '6869031022be478d8055',
                             '687ebde0cfeeab0eb9b3',
                             '69184b16e35a0a473926',
                             '69bdce7208b2e04e28a5',
                             '69c144524f50ee1efa3e',
                             '69f1ab706b55c737441d',
                             '6a31116ee40f9be22967',
                             '6b7d68459f50abbb2ef1',
                             '6bc25b60df92bfd2d8a1',
                             '6bc94dcb62357b1a0ec5',
                             '6bf173d1c73580ec9927',
                             '6d1cf559aabb3a112e3b',
                             '6d2f7106e0ec8ff958a0',
                             '6d461921d00282b00139',
                             '6ddcd213fb53134402bd',
                             '6e55ebae39a521709df3',
                             '6e89e4bf72bde8614de2',
                             '6ef3624a2af206d5c243',
                             '6efd813c97613ef444af',
                             '6f27f2fb476b58e20edd',
                             '705633989a1c1c13e186',
                             '70b68ff8892d02c9f515',
                             '70b92808070b570abbe2',
                             '70c54a9e988cff4b2088',
                             '718af6f97abc2e8c3028',
                             '735c3908d0d4bb860563',
                             '73784de457fd6fc7691b',
                             '73878695e20fa7efbdca',
                             '7388ebf10b1b6b494954',
                             '73e960ecd816f8557d06',
                             '742e95fe15ee9e7bbbdf',
                             '74622404321f3046ac79',
                             '7493535ec4407c074d90',
                             '74957326519675eb70b6',
                             '74da7e4fe91111c815d0',
                             '75103b988893d6a5567a',
                             '75cf595e589e4c2ac9c1',
                             '75e1cbf10c56f9ef5aef',
                             '767537b7ea6f79ca81f2',
                             '76a38edd3765e65a200a',
                             '76c57db2d6b376ef2cad',
                             '76e41dd905cbdb68ed71',
                             '77074c0725b297c5ac37',
                             '77449e02342ba95a3f87',
                             '77782049d82f9506c8b1',
                             '777e361f75ff92fdd540',
                             '78515f258b21ac80520e',
                             '7865ef328df5cc5e4458',
                             '790e4998704633f721c7',
                             '79551cc4e6db7b07d3cc',
                             '795b6ba880d5ee9d837d',
                             '7981d588d7c09979bec6',
                             '79b355ab729ecb591583',
                             '79bdf69e03dfabffdeca',
                             '79d355040b9baadf7a24',
                             '79e8c4b9d83eebc6122d',
                             '7a18ebaef5ec570c0747',
                             '7b3ff108756b109f492f',
                             '7c116ac8457b293bc325',
                             '7c151edab923c0f217a6',
                             '7c1b45dc180ee2e17b7c',
                             '7c1f1f331766bbd9ef7d',
                             '7c577339a8a0b6a1cec6',
                             '7c7007a16272ec21a1e6',
                             '7db21eb464e0e0361c2c',
                             '7e0bf70b83aa4d312dba',
                             '7e4aa0411274460def6b',
                             '7e67169116e30b929914',
                             '7e82a082b2c587421494',
                             '7ef9aa2486c6559fcbbd',
                             '7f36fa9807acd2238076',
                             '7f85a68f557275f91829',
                             '7ff2c3ff5755d021045f',
                             '7fff86f8137a21c75804',
                             '803fce1a5800682628ee',
                             '8067bbf4070af4212678',
                             '80d6d3db48a6d2d65299',
                             '80fb875ad5ea10cda899',
                             '8128c65410c0b502bbe7',
                             '81b40cfbc170db154648',
                             '81ba1e1a2373cd96ec16',
                             '826049bd55bdb64d710c',
                             '8263ca991310f5e66c21',
                             '82676b43e6bdb624f28b',
                             '82b49e2038d8eaf38207',
                             '832e4a747de3e76cc45a',
                             '83a67118f38570b5810c',
                             '83c90fcefa57b500851d',
                             '845828bc871ee14ecab9',
                             '84977dbd1c395b7e3d13',
                             '84c8361fb030106754a2',
                             '84d50abaf2053f6d1caa',
                             '84ef161bcc83c6caa6c4',
                             '852047f63e908b3a0d6f',
                             '85e06a79139a7a82a6a8',
                             '85f183fcfcec3143b514',
                             '86342878689b97f55d45',
                             '865f27ced3188e2f73e8',
                             '868484f2a3934915b126',
                             '87698ca6316d402e42ef',
                             '876a90222a99a44cf629',
                             '87a21cea7354f1df2f9f',
                             '87c6e78506af9019c3c4',
                             '87decd8f96e53ee3ad73',
                             '8826b932244f464649b4',
                             '8829c960e26b8062b8d0',
                             '8831e49d4d153ec75061',
                             '88f01aa62bd37f32941b',
                             '88f56229d84385edf0cd',
                             '894a5b063c550cda7888',
                             '894cb8a6f16da6ef30d2',
                             '899a8be1b5e3176ce5e4',
                             '89f4efafb8c5271644b2',
                             '8a0780ffbe97f1477267',
                             '8a597d4626eb088f3cea',
                             '8b196799fb0a64477dab',
                             '8b41476b0298672b9d9e',
                             '8bf9bbaf96eba7c6b0ad',
                             '8c40fc0293dfc0504847',
                             '8c5c4faaa555202e9c30',
                             '8c5fa05b87cfacb6cc56',
                             '8cb2cea62043e76eb649',
                             '8d4a3ddb234f3712eda0',
                             '8d6946f7ac191693b58b',
                             '8d74408d0333d33c4641',
                             '8e957f59af33fcf7b3b7',
                             '8ed67a93cca32cd54282',
                             '8f271c5440ac8d3245f3',
                             '8f48a8e10e1e436192a9',
                             '8f8bbc48598097229f11',
                             '8fb479c6a26910e5dac8',
                             '8feffa045a6fc2734e69',
                             '8ffe67b18734e3d372d8',
                             '9017ce3aa16c0f568ae4',
                             '90415a5a69f2bd72196d',
                             '90853b75e413d88710e0',
                             '90b45a48eeeb3a284c87',
                             '90da70e395fc111b489e',
                             '913b3663c000b8481b60',
                             '9149440206b075748fa1',
                             '9152701dde5463054ad0',
                             '91b9a772b2fcebd1e5ba',
                             '92032abfadc194a5347a',
                             '9248fa36e54a41859564',
                             '927426242cd7b20b68f5',
                             '92a08675ca1af824906c',
                             '92b92f335ff16d0ef692',
                             '92d9536f77ac72816920',
                             '92ee52443b7c8ec4d985',
                             '92f1a809197683a15675',
                             '9376eda3d9f378e047a9',
                             '9409aaa77ec85ed81cbf',
                             '943e3d7437a779ccdb51',
                             '9597c3c7c6edcc15c47f',
                             '96256dbfdff79e4c98d8',
                             '96afc066af9fb9ff6b98',
                             '970ad411445f32b8d922',
                             '97ffeeef2eabb4ff4a00',
                             '985a2ca16d40cecb38e5',
                             '98c20f3c36d9384a697a',
                             '98c80b848ab5fbaf0451',
                             '98d305b53c5093efffc4',
                             '99cf17f9b3fd82ea1863',
                             '9aa8c88f49de2375e31e',
                             '9b153c01aea181af3e8f',
                             '9b97cbb3e7b4a3da577f',
                             '9bab8547bdc8727f7e0f',
                             '9be02c709633373f80bd',
                             '9c1997b1578f165b05ed',
                             '9c29621080cce153bacf',
                             '9c7f8aa5793f6f931efd',
                             '9c89ca7a71ee74ebab3d',
                             '9c9ad1f129a6add8b9a2',
                             '9cb9bf581556b232bbbe',
                             '9ce72518cd0584d79914',
                             '9cf1abd7fbe776b86bec',
                             '9d5c7b4da82ac8a82546',
                             '9d5ff01c33a20fddc369',
                             '9d8a2e73b574c5483c0e',
                             '9e0b5277974d9091d8b7',
                             '9e1df1e3ee2b584bae01',
                             '9f06e55bb0b497f8725f',
                             '9f3d3411e5f5495d6372',
                             '9f68a43dbb6f7c7fc0cb',
                             '9faa5b31ba9edab2fa7c',
                             '9fc6718e0386e2519255',
                             '9ffe8dff046c5fdb66a4',
                             'a0132b975b77c01ccd2e',
                             'a02911ddf05a17a28878',
                             'a0340d1f433cd65e0bb3',
                             'a047ac2131bfb44c2885',
                             'a0605f6926039be816ef',
                             'a083ea4d537599a940fd',
                             'a0f5b56bf257e1b3105d',
                             'a107b1b33c454bfee887',
                             'a1371b7f5c70d7ad78d1',
                             'a1706be6df3dc271ac1c',
                             'a21a8b78c384b87cc378',
                             'a21bcb4701e5e016af9d',
                             'a2441a52e786225fc591',
                             'a2ade948bc5e134659d4',
                             'a2d6bdcacb011eac5189',
                             'a2efbbdffe75290f4df0',
                             'a3416942bdda04d7c9c1',
                             'a349037e1eadea3a3612',
                             'a36a9709a1ab9609df0a',
                             'a3b15241e0a0727d0b99',
                             'a3b46380cf6865d40759',
                             'a3c945bc0fdfa84ed128',
                             'a43b79b460f3c6a7ffe2',
                             'a4ab119328eb280103bc',
                             'a4abd2aaf96af7d54197',
                             'a4bcaaa500d9028e5348',
                             'a4cc56fa50f7255c00df',
                             'a4d8abc400cd0e120d01',
                             'a4f5bf70d15859ee75d4',
                             'a516b991d2ec86162177',
                             'a51adce480395886a25a',
                             'a604f22bd6812a13dae4',
                             'a65de871625fb0caefba',
                             'a7c2e5ddf3e618c9d5a7',
                             'a7d19485da8bcf1c6b3e',
                             'a7dea279478c1864896d',
                             'a7eff238026548ea27be',
                             'a810305826b6fd1edae8',
                             'a8a31452d7a981536508',
                             'a8aaa7fcb4ea1274c3e8',
                             'a8cd4f348d18a167d69b',
                             'a90c56238d3fd3105e91',
                             'a9fe90756aee5ee4bea8',
                             'aa56208f70f0c70632e3',
                             'aaf66cc3706b2dbb5869',
                             'ab3e83bd6b00604e017f',
                             'aba88a453f21b383f4e4',
                             'abcc9ad3ae13c240a192',
                             'ac9ff0c2b1891dbec730',
                             'ad36d95d402725721323',
                             'ad750347fd655ce15390',
                             'ada56b174c135ae7b6f2',
                             'adf373936d53fc107687',
                             'adfdca13ffba0c87be2a',
                             'ae06fae9d2647473dfee',
                             'affb55c68aa4333f9e65',
                             'b0ef4e812dcc75304cf2',
                             'b11e26cf808ba8727d6b',
                             'b2ecb97357b85eb3f20d',
                             'b33d5925192cc0e92bef',
                             'b33d78ade103d7d1e358',
                             'b34d1640820c697b0312',
                             'b389e18a00472f4e23a6',
                             'b4153f30317ab2da5af3',
                             'b4b76e8a81e81b667996',
                             'b50d9001bd3ba7b34e72',
                             'b537368d246a27743a5a',
                             'b547dbb7dd983f27b243',
                             'b628495f3ba760acf411',
                             'b6427f4957c1805e6e63',
                             'b737d6ac11168a33d110',
                             'b83860d60b87ef1d5987',
                             'b88985605eed9e97190c',
                             'b8c2be874417347a87ba',
                             'b98599dfc1f7bf66cf74',
                             'b9b70b01dfa40dcb11f0',
                             'ba583563b53a0c24c031',
                             'ba9f27ecb540c85950c3',
                             'bab93acde6eaa15f280d',
                             'bacedebb302ef1ab2d5c',
                             'bb036ea966022e50ecad',
                             'bb24ca8eee4f51581f8d',
                             'bb7dab7dc9a5cc16d7d9',
                             'bca06f685e47b6e4119a',
                             'bce28c65c3cb87cfff62',
                             'bd0704ba4884785c6ef7',
                             'bd982db2dbb639f0f3f0',
                             'bdbb23954120e716df92',
                             'be3780c8dacf5bdffa5d',
                             'be691a3bb215a634f2dd',
                             'bf011e4e3c24972efeb1',
                             'bf1372e04d69e371fae7',
                             'bf1c15be0e90d5e9b232',
                             'bfe4ae8d67ceed92e068',
                             'c0962b4008cb210796a3',
                             'c0fa9247bd2fab6d67ac',
                             'c109a9d1a5ae2d6e2d5e',
                             'c166caf5085692612d55',
                             'c1d7fd20c2305eec4788',
                             'c3124a1a79a611b37374',
                             'c3d0e290c14bae2a843d',
                             'c458e760d7144004bb10',
                             'c48f8092b6fda47c63ef',
                             'c4cc06555eea357281d7',
                             'c4f28951cae5c03be203',
                             'c594624113f15ef94108',
                             'c61351c0e3e575f0059e',
                             'c6b0444728e4e1c65cb3',
                             'c74219fed04bc40a51bc',
                             'c777d9f895f8cab28840',
                             'c7c5132da70902e4a2c7',
                             'c8a4a75d1019ce6b054b',
                             'c8c648cf11d13f8d3c73',
                             'c8d3ea878db68cd12dd4',
                             'c96283f39b9a79584ced',
                             'c9aa584db22bc9ab3c3d',
                             'c9eee673dc5ba6a6539d',
                             'ca028323bb5fa5dbbcda',
                             'ca5d9369f10ac2910576',
                             'ca79274a72769d3b5f1f',
                             'ca8f863b316f989626f2',
                             'caed8664a59adf23a649',
                             'cb58524e31ba902ed8cc',
                             'cb7bbd11edf1e490fe28',
                             'cb7ef68c6cc03c2566cb',
                             'cb802163f4d132728562',
                             'cbd74299857a646ce11e',
                             'ccd2fad0626ff7e0851d',
                             'cd24d0fc08e17f72422b',
                             'cd7bb450fc0735b77cac',
                             'cda156ea623de703cff3',
                             'cdb67aee48e4bdd02088',
                             'cdc7263b294c04c292f4',
                             'cdd09ced1312346f1e1b',
                             'cde1d04cf63c6b986d23',
                             'cdf7542f09819017a1d9',
                             'ce4b322b96009a6521dd',
                             'cf46d1e10c468cd61818',
                             'cf7f37b16147adb0aea0',
                             'd05594bf06450c61bd27',
                             'd06e3c01eeffa3b0cfb5',
                             'd0c0c78755939a616abd',
                             'd0cd4743de3c15fa01d0',
                             'd0ffc0bf3e5247d98d8e',
                             'd11eb552df29f4e5b6ee',
                             'd12aa84c323907fb48c0',
                             'd16fd9edf37bf1f848a2',
                             'd18a904f8af362eb2756',
                             'd18c54d68721760ab7da',
                             'd213f29608769fb63835',
                             'd274863c738d371a06e6',
                             'd29f821840d5a9816e02',
                             'd2aebd9c73ecf9a76d51',
                             'd2e506483aecbc36ecfe',
                             'd3a18e6b9550e928a009',
                             'd3d059537b011778ba7c',
                             'd3e4dae96591b8bc0cc6',
                             'd40c6f4a937ef675d295',
                             'd424bab8cadd230ea343',
                             'd4925c4c9e15faa30223',
                             'd498a9405f6c7ef61f05',
                             'd4a1c8cb3e3db91bc723',
                             'd4e7ab69550939d6e62b',
                             'd528e47f1e103a0b5599',
                             'd56f90b864e88ab79313',
                             'd5a17d9b894076e1d5d8',
                             'd60b060f6c900aa0d627',
                             'd66f5266d6a7defb69c7',
                             'd7493d53e4cdcd1b9171',
                             'd74c61bd0a21994ded92',
                             'd7a4b21912f6b0fb482d',
                             'd7a7e3fa8e4d5c958dcb',
                             'd87e7d2ea329e9fee801',
                             'd88d5883c3052d821f1b',
                             'd8a785b01b1af3208664',
                             'd94c7db67e94c9b11de6',
                             'd9ec44958586306c49e9',
                             'da2a9c1a1b2f47a8391e',
                             'da3a96710cc262f1c660',
                             'da4b8625c0d9a143806a',
                             'da58df6b0c67848e81aa',
                             'da60466991be8b1462b5',
                             'da6e54a210dd10318e21',
                             'dacc28ebb6004aebbec4',
                             'db0895c3dd9defebdf03',
                             'db312df40d26c8b54218',
                             'db4a59b8e9bd58126d78',
                             'dbba1be9c5392e44d40c',
                             'dc3d3877573efccc8ea5',
                             'dc51f6cfb46aa35f3f06',
                             'dcde390d5c5613fc5982',
                             'dcf835a146c0ef082640',
                             'ddf1b22d1144749952f1',
                             'de38ac07c859b609cdc9',
                             'de3b1ac1040276312900',
                             'de9f0f8cfbd46f8fabe0',
                             'decf198e24583d27e823',
                             'def032bf660003803088',
                             'def30388fbba235792e8',
                             'df5127117e7e2c117483',
                             'dfb3b41b60e4f70e2e72',
                             'dfd3d40a1668bd395c5f',
                             'e07ee6b4180e92af1eb5',
                             'e0a5246d25e3b84e3ef9',
                             'e0afa8ad736bf2331022',
                             'e197ba64f5d54f339a58',
                             'e1ca923a9a6de10641c0',
                             'e1d9c257f88a8ee19ae2',
                             'e1fdb1a546ac111f6ffb',
                             'e2024ea3f3fc6ef40ce0',
                             'e2c4f0019adb65886fbf',
                             'e2fb849dfec3b9523bc1',
                             'e2fff8559bdcc0d605ef',
                             'e39c5189aed835d7bd1d',
                             'e3bfedc1246008b89985',
                             'e3f0e13b130a48eb3ed5',
                             'e40c8b76b690040ebe3d',
                             'e428aebb4c4b78fc56b9',
                             'e49212ce6d412537dc41',
                             'e4cc4ddcb90f52ceeaa0',
                             'e5a9fe0962ab9acedb19',
                             'e60ac13b26ad3232ddd9',
                             'e62b3cd317c24e669cce',
                             'e661cf10b4b83b9b984d',
                             'e664d7343e8a1500dc16',
                             'e6a98bf9349a55390a9f',
                             'e7232abac6b60bd7578d',
                             'e7264b30c3ee9d8f687a',
                             'e72ce2aa09aec308a707',
                             'e787747cf0e500198325',
                             'e7b4a090654c0aa85709',
                             'e812452412a847f678ce',
                             'e856a209bc153692fbbc',
                             'e8a685ecee88e5c232dc',
                             'e8aca6e2579dce82c166',
                             'e943de166e0816bb00f0',
                             'e9545880797ddcce2707',
                             'e99ba8e6482b1c4bb86b',
                             'e99fb25476b4f882cf8c',
                             'e9cfeb01f61c1b772688',
                             'e9f96ccf6bfd9ec99c31',
                             'ea4c2f2ceb492c273dfd',
                             'ea5185c1fe9a17df967d',
                             'ea5ff23bd14038ec8bad',
                             'eae332c747b2b11f00dc',
                             'eb963aafb21a97e51be6',
                             'ec8fb91f40cf463777ce',
                             'ec99ce30e9571d91d577',
                             'ecf880230fec35fe0ccb',
                             'ed5134efdc699f79b96b',
                             'ee1542d79a577a2641e9',
                             'eece7c234e251c4e2300',
                             'ef986674829768b2fe1d',
                             'efc522e47bc837cea545',
                             'efc7cba454d463fb0823',
                             'f0676df4d47e743b103f',
                             'f0856f60757c4cc176f2',
                             'f0cfac80f63ab71907e6',
                             'f13317cc5c31a82cc807',
                             'f19b802c26b6bc4f16db',
                             'f1b1d45b3d4cf5f97517',
                             'f1d3aac499a18571f222',
                             'f2c1f1403e239c717a28',
                             'f33249e15b010f1e8961',
                             'f3e14156d76ecaee877c',
                             'f40daeaf8e3c50859c24',
                             'f40f69fa7421a1cff8da',
                             'f47c3cf71b668cc43163',
                             'f55245de07509ffdbd5d',
                             'f55e38fa5c913e57ed54',
                             'f6270d25709becd2ca2a',
                             'f6b319fb22f253733dd6',
                             'f6bc67ef984e93658230',
                             'f6f9b62b6cafe5d85547',
                             'f739934097f7c3f4aca3',
                             'f7e1feb9e616c0d8b76b',
                             'f81623f7ce1f83db7132',
                             'f84a48820d6ce777e177',
                             'f87349cdadfbda5be58f',
                             'f93041ff9238b9543153',
                             'f949a48a0c2333cce11c',
                             'f9a1474b69661b1ceb6b',
                             'f9b6c022582b7fcf1831',
                             'f9c89313cae45a5fdb1c',
                             'fa1506560e39dd2aa14c',
                             'fa2cc3c56126c4de8f03',
                             'fa99f0259d0b0764fa72',
                             'fab885f2e23eb17932c7',
                             'fac5c18489a4bba7e9fc',
                             'fbb25a726a2467eeced0',
                             'fbdf08439eb0c4944043',
                             'fc3affe041a5b0786ae9',
                             'fc66f473d45fd0c1c46a',
                             'fcb79bc9475bc32fb801',
                             'fcc04108b1e332a8530d',
                             'fce3275e33805656e9dc',
                             'fd10d5b5870e918dab23',
                             'fea17abd1052b34951dd',
                             'fea7469f274e4c923b34',
                             'fec02993616bb99d7966',
                             'ff0007571004b13b489a',
                             'ff0f4c754f5640185fee',
                             'ff647034f21637737e80',
                             'ff91d121914c58d573f2',
                             'ffaddedc42fe709a5442',
                             'ffba2a3abebbb4d52fe2',
                             'ffdcd411ca171846fc48',
                             'ffec12542d0b7da27a5c']}


def require(condition, reference):
    if not condition:
        raise ValueError(reference)


def guard_dispositions(guards=None):
    guards = CONTRACT['guards'] if guards is None else guards
    result = {}
    for checks,ids in ENFORCED_GUARDS.items():
        require(checks and all(callable(globals().get(check)) for check in checks),'guard check ID missing')
        for identity in ids:
            require(identity not in result,'duplicate guard disposition: '+identity)
            result[identity] = dict(status='enforced',check_ids=list(checks))
    for category,ids in OFFLINE_GUARDS.items():
        reason = OFFLINE_GUARD_REASONS[category]
        require(bool(reason),'empty offline reason')
        for identity in ids:
            require(identity not in result,'duplicate guard disposition: '+identity)
            result[identity] = dict(status='unenforceable_offline',reason=reason,category=category)
    wanted = {guard['id'] for guard in guards}
    require(len(wanted) == len(guards),'duplicate extracted guard')
    require(wanted == result.keys(),'unmapped/stale guards: '+repr(sorted(wanted-result.keys()))+
            '; stale='+repr(sorted(result.keys()-wanted)))
    return result


def contract_guards():
    # Cached only after exhaustive validation at import completion. Validating
    # 100k records must not repeat this unchanged source-policy audit 100k times.
    require(GUARD_COUNTS['extracted'] == len(CONTRACT['guards']),'contract guard count drift')
    require(GUARD_COUNTS['extracted'] == GUARD_COUNTS['enforced']+GUARD_COUNTS['unenforceable_offline'],
            'guard coverage incomplete')


def strict_json(data):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, 'duplicate JSON key: ' + key)
            value[key] = item
        return value

    def nonfinite(token):
        raise ValueError('nonfinite JSON number: ' + token)

    def finite_float(token):
        value = float(token)
        require(math.isfinite(value), 'nonfinite JSON number: ' + token)
        return value

    return json.loads(data, object_pairs_hook=pairs, parse_constant=nonfinite,
                      parse_float=finite_float)


def alternatives(spec):
    depth = start = 0
    for index, char in enumerate(spec):
        if char == '(':
            depth += 1
        elif char == ')':
            depth -= 1
        elif char == '|' and depth == 0:
            yield spec[start:index]
            start = index + 1
    yield spec[start:]


SHAPES = {tuple(sorted(fields)): name for name, fields in SCHEMAS.items()}


def split_contract_types(spec):
    result,depth,start = [],0,0
    for i,c in enumerate(spec):
        if c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
        elif c == ',' and depth == 0:
            result.append(spec[start:i])
            start = i+1
    result.append(spec[start:])
    return result


def contract_leaves(value, spec='BootstrapWitness', path=()):
    """Type every leaf by traversing declared contract edges, never key names."""
    if '|' in spec:
        choices = list(alternatives(spec))
        if value is None:
            # Retain optional scalar width even for absent values.
            spec = next((s for s in choices if s != 'null'),'null')
        else:
            candidates = [s for s in choices if s in SCHEMAS and type(value) is dict]
            spec = min(candidates,key=lambda s:len(set(value).symmetric_difference(SCHEMAS[s]))) if candidates else next(s for s in choices if s != 'null')
    if spec in SCHEMAS and type(value) is dict:
        for key,child in SCHEMAS[spec].items():
            if key in value:
                yield from contract_leaves(value[key],child,path+(key,))
    elif (spec.startswith(('array(','list(','tuple(')) or spec in CONTRACT['aliases']) and type(value) is list:
        if spec in CONTRACT['aliases']:
            yield from contract_leaves(value,CONTRACT['aliases'][spec],path)
            return
        if not value:
            yield path,spec
            return
        if spec.startswith('array('):
            _,child = split_contract_types(spec[6:-1]); children = [child]*len(value)
        elif spec.startswith('tuple('):
            children = split_contract_types(spec[6:-1])
        else:
            children = [spec[5:-1]]*len(value)
        for i,(item,child) in enumerate(zip(value,children)):
            yield from contract_leaves(item,child,path+(i,))
    else:
        yield path,spec


def typed(value, spec, path):
    choices = list(alternatives(spec)) if '|' in spec else [spec]
    if len(choices) > 1:
        for choice in choices:
            try:
                typed(value, choice, path)
                return
            except ValueError:
                pass
        raise ValueError(path + ': expected ' + spec)
    if spec in SCHEMAS:
        fields = SCHEMAS[spec]
        require(type(value) is dict, path + ': expected object ' + spec)
        if value.keys() != fields.keys():
            raise ValueError(path + ': missing=' + ','.join(sorted(set(fields)-set(value))) +
                             '; unknown=' + ','.join(sorted(set(value)-set(fields))))
        for key, item in value.items():
            typed(item, fields[key], path + '.' + key)
    elif spec.startswith('array(') or spec.startswith('tuple('):
        parts = split_contract_types(spec[spec.index('(')+1:-1])
        if spec.startswith('array('):
            size,child = parts
            children = [child]*int(size)
        else:
            children = parts
        require(type(value) is list and len(value) == len(children),path+': expected '+spec)
        for i,(item,child) in enumerate(zip(value,children)):
            typed(item,child,path+'['+str(i)+']')
    elif spec.startswith('list('):
        require(type(value) is list, path + ': expected array')
        for index, item in enumerate(value):
            typed(item, spec[5:-1], path + '[' + str(index) + ']')
    elif spec in CONTRACT['aliases']:
        typed(value,CONTRACT['aliases'][spec],path)
    elif spec in ('ip', 'ipv4_text', 'socket_address'):
        import ipaddress
        require(type(value) is str, path + ': IpAddr')
        if spec == 'socket_address':
            address, port = value.rsplit(':', 1)
            require(port.isascii() and port.isdecimal() and 0 <= int(port) <= 65535, path + ': port u16')
            if address.startswith('[') and address.endswith(']'):
                ipaddress.IPv6Address(address[1:-1])
            else:
                ipaddress.IPv4Address(address)
        else:
            parsed = ipaddress.ip_address(value)
            require(spec != 'ipv4_text' or parsed.version == 4, path + ': IPv4 address')
    elif spec in ENUMS:
        require(type(value) is str and value in ENUMS[spec], path + ': ' + spec + ' enum')
    elif spec in INTEGER_RANGES:
        lo, hi = INTEGER_RANGES[spec]
        require(type(value) is int and lo <= value <= hi, path + ': expected ' + spec)
    elif spec == 'f64':
        require(type(value) in (int, float) and math.isfinite(value) and value >= 0,
                path + ': expected finite nonnegative f64')
    else:
        valid = ((spec == 'null' and value is None) or
                 (spec == 'bool' and type(value) is bool) or
                 (spec == 'str' and type(value) is str) or
                 (spec == 'empty' and type(value) is list and not value))
        require(valid, path + ': expected ' + spec)



def typed_object(value, shape, path):
    require(shape in SHAPES, path + ': unknown object schema')
    typed(value, SHAPES[shape], path)


def objects(value, path='witness'):
    if type(value) is dict:
        yield path, value
        for key, item in value.items():
            yield from objects(item, path + '.' + key)
    elif type(value) is list:
        for index, item in enumerate(value):
            yield from objects(item, path + '[' + str(index) + ']')


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode()


def stdout_rows(record):
    rows = {}
    witness = None
    expected = ['secret_attachment_build_exit', 'secret_attachment_input',
                'secret_attachment_admission', 'secret_attachment_admission',
                'secret_attachment_descriptor', 'secret_quarantine_host',
                'secret_host_baseline', 'secret_attachment_gateway', 'owner_probe',
                'secret_attachment_owner_launcher', 'secret_attachment_environment',
                'case', 'LAB_SECRET_BOOTSTRAP', 'secret_attachment_controller']
    lines = record['stdout'].splitlines()
    require(len(lines) == len(expected), 'stdout: expected exactly 14 ordered lines')
    references = {}
    for number, (line, key) in enumerate(zip(lines, expected), 1):
        if key == 'LAB_SECRET_BOOTSTRAP':
            require(line.startswith(key + ' '), 'stdout line ' + str(number) + ': witness prefix')
            witness = strict_json(line.split(' ', 1)[1])
        else:
            row = strict_json(line)
            require(type(row) is dict and key in row, 'stdout line ' + str(number) + ': ' + key)
            shape = tuple(sorted(row))
            typed_object(row, shape, 'stdout[' + str(number) + ']')
            require(set(row) == ({'case', 'result'} if key == 'case' else {key}),
                    'stdout line ' + str(number) + ': extra row keys')
            rows.setdefault(key, []).append(row if key == 'case' else row[key])
        references.setdefault(key, []).append(number)
    return witness, rows, references


def frozen_bindings(record):
    # The original reservation binds all 34 inputs, including the archive
    # manifest and both controller programs. Do not import or execute them.
    reservation_bytes = (ROOT / RESERVATION).read_bytes()
    require(hashlib.sha256(reservation_bytes).hexdigest() ==
            'b080960ec82c23bfe9f802e033886bb75b5fc288b4e56df336b400c57a369140',
            'reservation frozen SHA256')
    reservation = strict_json(reservation_bytes)
    require(reservation['run'] == 410 and reservation['candidate'] == str(CANDIDATE)
            and reservation['mode'] == 'success' and reservation['one_shot_budget'] == 1,
            'reservation run/candidate/mode/budget')
    seen = set()
    for binding in reservation['bindings']:
        relative = Path(binding['path'])
        require(not relative.is_absolute() and '..' not in relative.parts,
                'reservation binding outside repository')
        require(str(relative) not in seen, 'duplicate reservation binding')
        seen.add(str(relative))
        retained = ROOT/'target/run410-evidence/files'/relative
        historical = retained if str(relative) in (
            'tools/rust-v2-lab/fresh-baseline.py',
            'tools/rust-v2-lab/phase3-readonly-preflight.py') else ROOT/relative
        require(sha(historical) == binding['sha256'], 'reservation historical binding: '+str(historical))
    require(len(seen) == 34, 'reservation: 34 mandatory bindings')
    candidate = strict_json((ROOT / CANDIDATE).read_bytes())
    require(candidate['source_commit'] == SOURCE_COMMIT, 'candidate.source_commit')
    require(record['source_binding'] == candidate['binding'], 'record.source_binding')
    require(record['source_binding']['source_commit'] == SOURCE_COMMIT, 'record source commit')
    require(record['source_archive_sha256'] == candidate['source_sha256'] ==
            sha(ROOT / CANDIDATE.parent / 'source.tar'),
            'record.source_archive_sha256')
    for key, name in [('artifact_sha256', 'amd64.payload'), ('context_sha256', 'amd64.context.tar')]:
        require(record[key] == candidate['platforms']['amd64'][key] == sha(ROOT / CANDIDATE.parent / name),
                'record.' + key)
    directory = ROOT / CANDIDATE.parent / reservation['label']
    for key, original, retained in [
        ('runner_sha256', 'run-frozen-secret-bootstrap410.py', 'controller-runner.py'),
        ('guest_sha256', 'secret-bootstrap.guest.py', 'controller-guest.py'),
        ('context_checker_sha256', 'attachment_context_check.py', 'controller-context.py'),
        ('host_declaration_builder_sha256', 'quarantine_host_declaration.py', 'controller-host-declaration.py'),
        ('baseline_declaration_builder_sha256', 'host_baseline_declaration.py', 'controller-baseline-declaration.py'),
    ]:
        require(record[key] == sha(ROOT / 'target/platform-lab' / original) == sha(directory / retained),
                'record.' + key + ': original/retained bytes')
    for key, original, retained in [
        ('host_baseline_template_sha256', 'authored-host-baseline-debian-clean-x86_64.json', 'controller-authored-baseline.json'),
        ('baseline_reconciliation_sha256', 'host-baseline-reconciliation-debian-clean-x86_64.json', 'controller-baseline-reconciliation.json'),
    ]:
        require(record[key] == sha(ROOT / CANDIDATE.parent / original) == sha(directory / retained), 'record.' + key)
    require(record['platform'] == reservation['platform'] == 'debian-clean-x86_64', 'record.platform')
    require(record['run_reservation'] == dict(path=str(RESERVATION), sha256=hashlib.sha256(reservation_bytes).hexdigest(),
            claim=str(CLAIM), continuity='fresh-lab', historical_raw_records_recovered=False), 'record.run_reservation')
    claim = strict_json((ROOT / CLAIM).read_bytes())
    require(claim['reservation'] == str(RESERVATION) and claim['reservation_sha256'] == sha(ROOT / RESERVATION)
            and type(claim['run']) is int and claim['run'] == 410
            and type(claim['budget_remaining']) is int and claim['budget_remaining'] == 0
            and claim['controller_boot_id'] == reservation['controller_boot_id'], 'consumed claim binding/budget')
    require(record['guest_boot_id'] == reservation['guest_boot_id'], 'record.guest_boot_id / reservation')


def bootstrap_success(w, record):
    require(w['schema'] == 1 and w['fault'] == 0, 'witness.schema/fault')
    for key in ('failed_constructor', 'failure_retry', 'retained_result_writer'):
        require(w[key] is None, 'witness.' + key + ' must be null on success')
    for key in ('bootstrap_all_scopes_acknowledged', 'bootstrap_context_created', 'parent_pristine',
                'whole_chain_retained_after_drop', 'original_nine_contexts_retained_after_drop',
                'operational_context_retained_after_drop', 'bootstrap_context_retained_after_drop'):
        require(w[key] is True, 'witness.' + key)
    require(w['canonical_negative_checks'] == CANONICAL_NEGATIVE_CHECKS, 'witness.canonical_negative_checks: expected 39')
    require(w['result_writer_held'] is False, 'witness.result_writer_held')
    require(record['exit_code'] == 0 and record['result'] == 'PASS_PARTIAL_SECRET_BOOTSTRAP'
            and record['component_test_mode'] == 'secret_bootstrap_success', 'record success classification')
    for key, negatives, index in [('own_intent_polling', 12, 90), ('own_query_intent_polling', 6, 87)]:
        intent = w[key]
        require(intent['held_pending_polls'] == 2 and intent['negative_checks'] == negatives
                and intent['released'] is True and intent['queued_polls'] == 1, 'witness.' + key)
        writer = w['preparation']['writers'][index]
        require(intent['index'] == index and intent['pid'] == writer['pid']
                and intent['start'] == writer['start'] and writer['actual_wait_status'] == 0
                and writer['verified_at'] is not None, 'witness.' + key + ': original intent writer')


def preparation_success(w):
    # attachment/operational/bootstrap.rs:1028-1069, specialized to fault=0.
    # These checks concern the final preparation. Earlier snapshots keep their
    # original continuation/drop flags; only the listed fields are retained.
    p, host = w['preparation'], w['host_addition']['preparation']
    for key in ('native_children_reaped', 'service_reserved', 'entry_links_absent',
                'entry_attempt_absent', 'entry_terminal_absent'):
        require(p[key] is True, 'preparation.' + key)
    for key in ('member_native_jobs_collected', 'canonical_pending', 'mutation_fenced'):
        require(p[key] is False, 'preparation.' + key)
    require(p['entry_phase'] == 'creating', 'preparation.entry_phase')
    require(p['entry_producer'] == host['entry_producer'], 'preparation.entry_producer: unchanged host prefix')
    require(len(p['writers']) == 105 and len(host['writers']) == 87
            and p['writers'][:87] == host['writers'], 'preparation.writers: unchanged 87-writer host prefix')
    for key in ('wireguard', 'netfilter', 'producer_creation', 'producer_binding',
                'producer_binding_query', 'producer_query', 'quarantine_query',
                'movement_query', 'inspection', 'attachment', 'fresh_transport', 'host_link',
                'base_network', 'data_network', 'transport_network', 'canonical_owner_epoch'):
        require(p[key] == host[key], 'preparation.' + key + ': unchanged host prefix')


def charge_conservation(w):
    for key in ('charges_before_drop', 'charges_after_drop'):
        require(w[key] == [3, 3], 'witness.' + key + ': expected [3,3]')
    require(w['handoff']['charges_before'] == [5, 5] and w['handoff']['charges_after'] == [0, 0],
            'witness.handoff charges: expected [5,5] -> [0,0]')


def handoff(w):
    h = w['handoff']
    require(h['complete'] is True and h['complete_original_job_set'] == 20
            and h['historical_original_jobs'] == 15 and h['retired_suffix_jobs'] == 5
            and h['repeat_retirement_refusals'] == 5 and h['global_child_capacity_limit'] == 64,
            'witness.handoff: complete 20 = 15 historical + 5 suffix')
    require(h['duplicate_reservation'] is None and h['fence_counts'] is None
            and h['resources_collected'] is False, 'handoff: no failure reservation/cleanup')
    r = h['reservation']
    require(r['original_jobs'] == 15 and r['suffix_jobs'] == 5 and r['suffix_complete'] is True
            and r['suffix_failed'] is False and r['member_transfer_pending'] is False
            and r['global_transferred_ticket_limit'] == 2560 and r['member'] == w['preparation']['member'],
            'handoff.reservation: completed original job set')
    resources = h['resources']
    require(len(resources) == 5 and [a['kind'] for a in resources] == ['FixedNetfilter'] + ['FixedVeth']*4,
            'handoff.resources: five original suffix jobs')
    expected = [w['host_addition']['producer_binding']['observation']] + w['host_addition']['operations']
    identities = set()
    for resource, original in zip(resources, expected):
        identity = (resource['original_pid'], resource['original_start'])
        require(identity == (original['original_pid'], original['original_start']) and identity not in identities,
                'handoff.resources: original job identities')
        identities.add(identity)
        require(resource['actual_wait_status'] == 0 and resource['native_job_state'] == 'transferred_resources',
                'handoff.resources: actual status/state')
        for key in ('fully_retired', 'launch_charge_retired', 'lower_charge_required', 'lower_charge_retired',
                    'lower_gated_retirement_refused', 'transfer_started'):
            require(resource[key] is True, 'handoff.resources.' + key)
    require(h['preparation'] == w['host_addition']['preparation'], 'handoff.preparation: unchanged host prefix')


def no_authority(w, record, rows):
    for path, obj in objects(w):
        for key, value in obj.items():
            if key.endswith('_authorized') or key in ('multi_exit_runtime_proven', 'requirement8_complete'):
                require(value is False, path + '.' + key + ': authority must remain false')
    require(record['real_client_acceptance'] == 'NOT_RUN' and record['production_changes'] is False
            and record['provider_profiles_used'] is False and record['namespace_or_container_fixture'] is True
            and record['actual_gateway_is_inert'] is True, 'record component-only scope')
    descriptor = rows['secret_attachment_descriptor'][0]
    for key in ('profile_contents_read', 'docker_queried', 'container_mounts_allowed', 'production_startup_authorized'):
        require(descriptor[key] is False, 'descriptor.' + key)
    for key in ('secret_host_baseline', 'secret_quarantine_host'):
        require(rows[key][0]['host_authority_granted'] is False, key + '.host_authority_granted')


def owner_identity(w, record, rows):
    epoch = w['preparation']['canonical_owner_epoch']
    require(re.fullmatch(UNIT, epoch['unit']) is not None, 'witness canonical owner unit pattern')
    require(epoch['boot'] == record['guest_boot_id'], 'witness canonical owner boot / record.guest_boot_id')
    require(re.fullmatch(r'[a-f0-9-]{36}', epoch['boot']) is not None and epoch['pid'] > 1 and epoch['start'] > 0,
            'owner boot/pid/start')
    require(epoch['cgroup']['ino'] > 0 and re.fullmatch(r'[a-f0-9]{32}', epoch['invocation']) is not None
            and epoch['invocation'] != '0'*32, 'owner cgroup/invocation')
    require(rows['owner_probe'][0]['unit'] == rows['secret_attachment_descriptor'][0]['owner_unit'] == epoch['unit'],
            'owner_probe/descriptor/canonical owner unit')
    for path, obj in objects(w):
        if set(obj) == set(SCHEMAS['OwnerEpoch']):
            require(obj == epoch, path + ': original canonical owner epoch')
    env = rows['secret_attachment_environment'][0]
    for key in ('before', 'after'):
        require(env[key]['files']['boot']['status'] == 'bounded'
                and env[key]['files']['boot']['text'].strip() == epoch['boot'], 'environment.' + key + ': boot')


def monotonic_deadlines(w):
    for path, obj in objects(w):
        if type(obj.get('admission')) is list:
            admission = obj['admission']
            require(len(admission) == 3 and 0 < admission[0] <= admission[2] < admission[1]
                    and admission[1] == admission[0] + 2.
                    and admission[2] <= obj['requested_at'], path + ': original host admission window')
        if 'born_at' in obj:
            require(0 <= obj['born_at'] < obj['deadline'], path + ': born_at < deadline')
            require(obj['pid'] > 1 and obj['start'] > 0, path + ': native birth identity')
        if 'requested_at' in obj and 'deadline' in obj:
            start, end = obj['requested_at'], obj['deadline']
            require(0 <= start < end and end == start + 2., path + ': original two-second request window')
            birth = obj.get('birth')
            if birth is not None:
                require(start <= birth['born_at'] < end and birth['deadline'] == end, path + '.birth: original window')
            previous = birth['born_at'] if birth is not None else start
            for key in ('mounted_at', 'published_at', 'verified_at', 'accepted_at'):
                if obj.get(key) is not None:
                    require(previous <= obj[key] < end, path + '.' + key + ': within original window')
                    previous = obj[key]
            result = obj.get('result')
            if type(result) is dict and result.get('observed_at') is not None:
                require((birth['born_at'] if birth is not None else start) <= result['observed_at'] <= previous < end,
                        path + '.result.observed_at: born <= observed <= verified < deadline')
        if 'io_deadline' in obj:
            require(0 <= obj['queued_at'] <= obj['verified_at'] < obj['io_deadline'] <= obj['parent_deadline'],
                    path + ': queued <= verified < io_deadline <= parent_deadline')
    times = w['scope_process_verified_at']
    require(len(times) == 3 and times == sorted(times) and w['final_process_verified_at'] == times[-1],
            'witness.scope_process_verified_at/final_process_verified_at')
    for index, at in enumerate(times):
        query = w['queries'][index]
        writer = w['preparation']['writers'][87 + index * 6 + 5]
        require(writer['verified_at'] <= at < query['deadline'], 'scope process verification before original deadline')


def bootstrap_scopes(w, rows):
    p = w['preparation']
    # Canonical producer-binding validation (producer_binding.rs:114-130)
    # applies to its retained histories and original operation evidence too.
    binding_shapes = [set(SCHEMAS[name]) for name in ('ProducerBindingHistory', 'ProducerObservation')]
    for path, obj in objects(w):
        if set(obj) in binding_shapes:
            result = obj['result']
            require(result['namespace'] == obj['data'] and result['group'] == obj['group']
                    and result['policy'] == obj['policy'] and result['pins'] == obj['pins'],
                    path + ': producer-binding result identity/policy/six pins')
    require(len(w['operations']) == len(w['queries']) == len(p['bootstrap']) == len(p['bootstrap_queries']) == 3,
            'three Bootstrap scopes/queries/histories')
    require(len(p['writers']) == 105 and len(p['netfilter']) == 6 and len(p['host_link']) == 4,
            'canonical preparation: 105 writers / six policies / four host operations')
    previous = p['host_link'][3]['verified_at']
    scopes = [('host', rows['secret_attachment_gateway'][0]['host_network_namespace']),
              ('transport', [p['transport_network']['dev'], p['transport_network']['ino']]),
              ('data', [p['data_network']['dev'], p['data_network']['ino']])]
    for index, (scope, ns) in enumerate(scopes):
        op, q, h, qh = w['operations'][index], w['queries'][index], p['bootstrap'][index], p['bootstrap_queries'][index]
        identity = dict(dev=ns[0], ino=ns[1])
        require(op['scope'] == h['scope'] == scope and op['namespace'] == h['namespace'] == identity,
                'Bootstrap scope/namespace: ' + scope)
        require(qh['initial'] is None, 'Bootstrap query forbids initial evidence')
        require(q['kind'] == qh['kind'] == 'Bootstrap' + scope.title() + 'Recheck', 'query kind: ' + scope)
        for key in ('birth', 'requested_at', 'deadline', 'facts', 'verified_at'):
            require(q[key] == qh[key], 'query canonical history.' + key)
        require(q['facts']['pid'] == rows['secret_attachment_gateway'][0]['pid']
                and q['facts']['security'] == 'AppArmorBuiltinSeccomp', 'query original gateway PID/security')
        require(q['actual_wait_status'] == 0 and q['original_peer_receipt'] is True
                and q['handler_identity_claimed'] is False and q['listener_origin_pid'] == 1
                and q['listener_origin_uid'] == q['listener_origin_gid'] == 0, 'original Docker query receipt')
        for key in ('birth', 'requested_at', 'deadline', 'namespace', 'scope', 'request', 'query', 'policy', 'pins', 'group', 'result'):
            require(op[key] == h[key], 'Bootstrap operation/canonical history.' + key)
        require(op['accepted_at'] == h['verified_at'] and op['query'] == qh['request']
                and op['requested_at'] == q['requested_at'] and op['deadline'] == q['deadline'], 'Bootstrap query/ack/request binding')
        require(previous <= op['requested_at'] <= q['birth']['born_at'] <= q['verified_at'] <= op['birth']['born_at']
                <= op['result']['observed_at'] <= op['accepted_at'] <= w['scope_process_verified_at'][index]
                < op['deadline'], 'Bootstrap ordered query/birth/observation/ack/process')
        previous = op['accepted_at']
        require(op['result']['namespace'] == op['namespace'] and op['result']['group'] == op['group']
                and op['result']['policy'] == op['policy'] and op['result']['pins'] == op['pins'], 'Bootstrap result identity/policy/pins')
        policy = p['netfilter'][index*2+1]
        require(policy['kind'] == 'initial_quarantine' and policy['scope'] == scope
                and all(policy[k] is not None for k in ('birth', 'result', 'verified_at')),
                'Bootstrap completed initial quarantine policy in original scope')
        require(op['policy'] == policy['policy'] and h['creation'] == p['producer_creation']
                and op['group'] == p['producer_creation']['group'] and op['parent'] == p['producer_creation']['parent']
                and op['name'] == p['producer_creation']['name'], 'Bootstrap original producer and policy')
        pins = op['pins']
        require(len(pins) == 8 and all(len(pin) == 3 for pin in pins)
                and len({tuple(pin[:2]) for pin in pins}) == 8
                and pins[0][:2] == [op['parent']['dev'], op['parent']['ino']]
                and pins[1][:2] == [op['group']['dev'], op['group']['ino']]
                and all(pin[0] == op['parent']['dev'] and pin[1] > 0 for pin in pins), 'Bootstrap eight original pins')
        require(op['original_pid'] == op['birth']['pid'] and op['original_start'] == op['birth']['start']
                and op['actual_wait_status'] == 0 and op['native_job_state'] == 'born'
                and op['borrowed_registration_count'] == 2 and op['registered_native_slots'] == 25,
                'Bootstrap native identity/registration/status')
        for key in ('acknowledged', 'native_born', 'complete_native_registration', 'context_retained',
                    'durable_birth_released', 'eof', 'bootstrap_installation_observed', 'original_registration_slots_verified'):
            require(op[key] is True, 'Bootstrap operation.' + key)
        for stage, writer in enumerate(p['writers'][87 + index*6:93 + index*6]):
            phase = 'bootstrap_' + scope + '_' + ('query_' if stage < 3 else '') + ('intent', 'birth', 'result')[stage % 3]
            require(writer['phase'] == phase and writer['actual_wait_status'] == 0
                    and writer['io_deadline'] == writer['parent_deadline'] == op['deadline']
                    and op['requested_at'] <= writer['queued_at'] < op['deadline'], 'Bootstrap original writer phase/status/window')
    for path, obj in objects(w):
        for key in ('request', 'policy', 'query', 'configuration', 'declaration', 'host_declaration'):
            if type(obj.get(key)) is list and obj[key]:
                require(len(obj[key]) == 32 and all(type(n) is int and 0 <= n <= 255 for n in obj[key])
                        and any(obj[key]), path + '.' + key + ': nonzero 32-byte digest')


def canonical_histories(w, rows):
    host = dict(zip(('dev','ino'), rows['secret_attachment_gateway'][0]['host_network_namespace']))
    member = w['preparation']['member']
    descriptor = rows['secret_attachment_descriptor'][0]
    allocation = descriptor['allocation']
    exit_record = next(e for e in allocation['exits'] if e['exit_id'] == member)
    for path, p in objects(w):
        if 'canonical_owner_epoch' not in p:
            continue
        preparation_idle(p)
        require(p['member'] == member, path + ': original member')
        # Every retained snapshot is already past successful DATA publication.
        require(p['base_network'] == p['data_network'] == p['attachment']['source'], 'published DATA namespace')
        mount = p['attachment']
        require(all(re.fullmatch(r'[a-f0-9]{64}',mount['origin'][key]) is not None
                    for key in ('launch','staging','container')) and mount['origin']['process_start'] > 0
                and any(mount['origin']['public_result']), 'original admitted Origin digest/identity')
        require(mount['name'] == exit_record['data_namespace'], 'canonical DATA namespace name')
        require(mount['origin']['network'] == mount['source'] and mount['directory']['ino'] > 0
                and mount['source']['ino'] > 0 and mount['placeholder']['identity']['ino'] > 0
                and mount['placeholder']['identity']['dev'] == mount['directory']['dev']
                and mount['placeholder']['mode'] == 0o100600
                and p['inspection']['verified_at'] <= mount['requested_at']
                and mount['query']['requested_at'] == mount['requested_at']
                and mount['query']['deadline'] == mount['deadline']
                and mount['mounted_at'] <= mount['query']['birth']['born_at']
                and mount['query']['verified_at'] <= mount['published_at'], 'DATA mount completion chain')
        original_facts = p['inspection']['facts']
        require(p['inspection']['kind'] == 'Recheck' and p['inspection']['initial'] is not None
                and p['inspection']['initial']['facts'] == original_facts
                and p['inspection']['initial']['request'] != p['inspection']['request']
                and p['inspection']['initial']['birth']['deadline'] == p['inspection']['deadline']
                and p['inspection']['requested_at'] <= p['inspection']['initial']['birth']['born_at']
                <= p['inspection']['initial']['verified_at'] <= p['inspection']['birth']['born_at'],
                'original initial/recheck inspection')
        queries = [('inspection',p['inspection'],'Recheck'), ('mount query',mount['query'],'AttachmentRecheck')]
        for key, kind in [('movement_query','MovementRecheck'), ('quarantine_query','QuarantineRecheck'),
                           ('producer_query','ProducerRecheck'), ('producer_binding_query','ProducerBindingRecheck')]:
            if p[key] is not None:
                queries.append((key,p[key],kind))
        for i,q in enumerate(p['bootstrap_queries']):
            if q is not None:
                queries.append(('bootstrap query',q,('BootstrapHostRecheck','BootstrapTransportRecheck','BootstrapDataRecheck')[i]))
        for key,q,kind in queries:
            require(q['kind'] == kind and q['facts'] == original_facts and 1 < q['facts']['pid'] <= 2**31-1
                    and (q['initial'] is None) == (kind != 'Recheck'), 'canonical query kind/initial/facts: ' + key)
        fresh = p['fresh_transport']
        if fresh is not None:
            fm = fresh['mount']
            require(fresh['host'] == host and fresh['data'] == p['data_network']
                    and fresh['source']['ino'] > 0 and fresh['source'] not in (host, fresh['data'])
                    and fresh['directory']['ino'] > 0 and fresh['name'] == exit_record['transport_namespace'] and fresh['requested_at'] >= mount['published_at']
                    and fm['source'] == fresh['source'] == p['transport_network']
                    and fm['directory'] == fresh['directory'] and fm['name'] == fresh['name']
                    and fresh['verified_at'] <= fm['requested_at']
                    and fm['placeholder']['identity']['dev'] == fm['directory']['dev']
                    and fm['placeholder']['identity']['ino'] > 0 and fm['placeholder']['mode'] == 0o100600,
                    'fresh transport creation/mount chain')
        wireguard = p['wireguard']
        require(len(wireguard) in (0,3,5), 'retained completed wireguard prefix')
        for i,h in enumerate(wireguard):
            kind = ('sockets','provision','query','data_sockets','move')[i]
            require(h['kind'] == kind and h['namespace'] == (p['data_network'] if i == 3 else p['transport_network'])
                    and h['namespace']['ino'] > 0, 'wireguard original kind/namespace')
            require(h['requested_at'] >= (wireguard[i-1]['verified_at'] if i else fresh['mount']['published_at']),
                    'wireguard ordered completion')
            require(h['configuration'] == wireguard[0]['configuration'], 'wireguard immutable configuration')
            r = h['result']
            require(r['namespace'] == (p['data_network'] if i == 4 else h['namespace'])
                    and ((r['link'] is None and r['wireguard'] is None) if i in (0,3)
                         else (r['link'] is not None and r['wireguard'] is not None)), 'wireguard result contract')
            # attachment/provision.rs:1002-1005 and movement.rs:824-835.
            # The booleans on the enclosing witness cannot establish link state.
            if i not in (0,3):
                require(r['link']['up'] is False and r['link']['kind'] == 'wireguard',
                        'WireGuard result must remain down and kind wireguard')
            if i == 4:
                q = p['movement_query']
                require(h['destination'] == p['data_network'] != h['namespace'] and h['movement_query'] == q['request']
                        and h['requested_at'] == q['requested_at'] and h['deadline'] == q['deadline']
                        and h['birth']['born_at'] >= q['verified_at'], 'movement canonical query binding')
        policies = p['netfilter']
        require(len(policies) in (0,6), 'retained six policy history')
        for i,h in enumerate(policies):
            scope = ('host','transport','data')[i//2]
            ns = host if i//2 == 0 else p['transport_network'] if i//2 == 1 else p['data_network']
            require(h['kind'] == ('sockets' if i%2 == 0 else 'initial_quarantine') and h['scope'] == scope
                    and h['namespace'] == ns and h['result']['namespace'] == ns and h['result']['policy'] == h['policy']
                    and (h['result']['observed_at'] is None) == (i%2 == 0), 'canonical completed policy kind/scope/result')
            require(h['requested_at'] > 0 and h['requested_at'] >= wireguard[4]['verified_at']
                    and h['configuration'] == wireguard[4]['configuration'], 'canonical policy configuration/order')
            if i:
                require(h['requested_at'] >= policies[i-1]['verified_at']
                        and h['host_declaration'] == policies[i-1]['host_declaration']
                        and (i%2 == 0 or h['policy'] == policies[i-1]['policy']), 'canonical policy predecessor')
            if i == 5:
                q = p['quarantine_query']
                require(h['query'] == q['request'] and h['requested_at'] == q['requested_at']
                        and h['birth']['born_at'] >= q['verified_at'], 'DATA policy canonical query')
            else:
                require(h['query'] is None, 'policy without DATA query')
        creation, binding = p['producer_creation'], p['producer_binding']
        if creation is not None:
            q = p['producer_query']
            require(creation['query'] == q['request'] and creation['requested_at'] == q['requested_at']
                    and creation['deadline'] == q['deadline'] and creation['birth']['born_at'] >= q['verified_at']
                    and creation['data'] == p['data_network'] and creation['parent']['ino'] > 0
                    and creation['group']['ino'] > 0 and creation['group']['dev'] == creation['parent']['dev']
                    and creation['group'] != creation['parent']
                    and creation['name'] == exit_record['nft_table']+'-g'+str(allocation['generation'])+'-health'
                    and q['requested_at'] >= policies[5]['verified_at'], 'canonical producer creation')
        if binding is not None:
            q = p['producer_binding_query']
            require(binding['creation'] == creation, 'producer binding original creation')
            same_fields(binding,creation,('parent','group','name','data'),'producer binding original source')
            require(binding['data'] == p['data_network'] and binding['query'] == q['request']
                    and binding['requested_at'] == q['requested_at'] and binding['deadline'] == q['deadline']
                    and creation['verified_at'] <= q['requested_at'] <= q['verified_at'] <= binding['birth']['born_at']
                    and binding['policy'] == policies[5]['policy'], 'producer binding canonical DATA/query/policy')
            pub = p['entry_producer']
            require(pub is not None and pub['binding'] == binding['request']
                    and pub['parent'] == binding['parent'] and pub['group'] == binding['group'],
                    'producer binding original publication')
            pins = binding['pins']
            require(pins[0][:2] == [binding['parent']['dev'],binding['parent']['ino']]
                    and pins[1][:2] == [binding['group']['dev'],binding['group']['ino']]
                    and all(pin[0] == binding['parent']['dev'] and pin[1] > 0 for pin in pins),
                    'producer binding six original pins')
        for i,h in enumerate(p['host_link']):
            require(h['kind'] == ('transport_sockets','pair','host_sockets','move')[i]
                    and h['host'] == host and h['namespace'] == (host if i == 2 else p['transport_network'])
                    and h['admission'][0] >= binding['verified_at']
                    and (h['addition'] is not None) == (i == 3), 'host canonical kind/namespace/admission/addition')
            if i:
                previous = p['host_link'][i-1]
                same_fields(h,previous,('declaration','admission','host'),'host canonical original admission')
                require(h['requested_at'] >= previous['verified_at'], 'host ordered original completion')
            r = h['result']
            require(r['namespace'] == (host if i == 3 else h['namespace']), 'host result namespace')
            if i in (0,2):
                require(r['host'] is None and r['peer'] is None, 'host sockets result')
            elif i == 1:
                a,b = r['host'],r['peer']
                require(a['kind'] == b['kind'] == 'veth' and a['up'] is b['up'] is False
                        and 0 < a['index'] != b['index'] > 0 and a['peer_index'] == b['index']
                        and b['peer_index'] == a['index'] and a['name'] == exit_record['host_interface']
                        and b['name'] == exit_record['data_interface']
                        and a['alias'] == b['alias'] == 'vprouter-v2:'+allocation['deployment_id']+':'+str(allocation['generation'])+':'+member,
                        'host original down pair')
            else:
                old = p['host_link'][1]['result']
                a,b = dict(old['host']),dict(old['peer'])
                a['index'] = b['peer_index'] = h['addition'][1]
                require(r['host'] == a and r['peer'] == b
                        and h['addition'][1] == w['host_addition']['planned_host_link_index'], 'host move original pair result')


def same_fields(left, right, keys, reference):
    for key in keys:
        require(left[key] == right[key], reference + '.' + key)


# A registry entry names the observation, its canonical source, and every
# compared field (including aliases). No observed value chooses its own source.
# Paths are absolute in {witness, rows}; '*' captures an array index only.
P = ('witness', 'preparation')
HOST = ('witness', 'host_addition')
BINDING = HOST + ('producer_binding',)
ASSEMBLY = BINDING + ('assembly',)
QUARANTINE = ASSEMBLY + ('quarantine',)
MOVEMENT = QUARANTINE + ('movement',)
PROVISION = MOVEMENT + ('provision',)
ATTACHMENT = PROVISION + ('attachment',)


def binding_entry(name, observation, canonical, fields, mode='equal', guards=()):
    pairs = tuple((tuple(a.split('.')), tuple(b.split('.'))) if isinstance(a, str)
                  else (a,b) for a,b in
                  ((f,f) if isinstance(f,str) else f for f in fields))
    return dict(name=name, observation=observation, canonical=canonical,
                fields=pairs, mode=mode, guards=guards)


def make_binding_registry():
    registry = []
    def add(name, observation, canonical, fields, mode='equal', guards=()):
        registry.append(binding_entry(name,observation,canonical,fields,mode,guards))

    # These are the canonical recorded roots, not observations of another
    # serialized object. Domain/order/publication guards still run separately.
    # Native custody and the independent regeneration of digests are not implied.
    roots = ('attachment base_network birth bootstrap bootstrap_queries canonical_owner_epoch '
             'data_network deadline entry_producer fresh_transport host_link inspection '
             'member movement_query netfilter producer_binding producer_binding_query '
             'producer_creation producer_query quarantine_query requested_at transport_network wireguard writers').split()
    add('canonical_preparation',P,None,roots,'root',
        ('canonical_histories','bootstrap_scopes','owner_identity','writer_histories','monotonic_deadlines'))
    # Each retained preparation is a historical projection, with populated
    # histories/prefixes bound to the final history. Null/empty earlier stages
    # remain checked by retained_success and their exact stage cardinalities.
    for stage in (('witness','handoff'),HOST,BINDING,ASSEMBLY,QUARANTINE,MOVEMENT,PROVISION,ATTACHMENT):
        add('retained_preparation:'+'.'.join(stage),stage+('preparation',),P,roots,
            'projection',('preparation_success','retained_success'))

    # I9: provision.rs:878-885; kernel/fresh_transport.rs:498-505;
    # kernel/fresh_transport_mount.rs:852-861; owned/preparation/
    # fresh_transport.rs:112-120, fresh_mount.rs:115-120,452-453.
    add('transport_creation',PROVISION+('transport_creation',),P+('fresh_transport',),
        tuple(sorted(set(SCHEMAS['TransportWitness']) & set(SCHEMAS['FreshTransport']))))
    mount_fields = tuple(k for k in ('birth','requested_at','deadline','placeholder')
                         if k in SCHEMAS['MountHistory']) + (
                    ('original_source','source'),('original_directory','directory'))
    add('transport_mount',PROVISION+('transport_mount',),P+('fresh_transport','mount'),mount_fields)
    add('data_mount',ATTACHMENT+('mount',),P+('attachment',),mount_fields)
    add('validator_birth',ATTACHMENT+('validator',),P,('birth',))

    query_fields = tuple(sorted(set(SCHEMAS['Query']) & set(SCHEMAS['InspectionHistory'])))
    for name,observation,history in (
        ('attachment_recheck',ATTACHMENT+('second_query',),P+('inspection',)),
        ('postmount_query',ATTACHMENT+('postmount_query',),P+('attachment','query')),
        ('movement_query',MOVEMENT+('movement_query',),P+('movement_query',)),
        ('quarantine_query',QUARANTINE+('quarantine_query',),P+('quarantine_query',)),
        ('producer_query',QUARANTINE+('producer_query',),P+('producer_query',)),
        ('binding_query',BINDING+('query',),P+('producer_binding_query',)),
        ('bootstrap_queries',('witness','queries','*'),P+('bootstrap_queries','*'))):
        add(name,observation,history,query_fields)
    add('initial_query',ATTACHMENT+('first_query',),P+('inspection','initial'),('birth','facts','verified_at'))
    # Initial History intentionally omits its kind; the source discriminator is
    # fixed by owned/preparation/inspection.rs:142,864-875, not freely substitutable.
    add('initial_query_kind',ATTACHMENT+('first_query',),('expected','initial_query'),('kind',))
    add('initial_query_window',ATTACHMENT+('first_query',),P+('inspection',),('requested_at','deadline'))

    operation_fields = tuple(sorted(set(SCHEMAS['MovementOperation']) & set(SCHEMAS['WireguardHistory']))) + (('accepted_at','verified_at'),
                        ('original_pid','birth.pid'),('original_start','birth.start'))
    for name,observation,history,extra in (
        ('provision_operations',PROVISION+('operations','*'),P+('wireguard','*'),()),
        ('movement_operations',MOVEMENT+('operations','*'),P+('wireguard','*'),()),
        ('quarantine_operations',QUARANTINE+('operations','*'),P+('netfilter','*'),('scope',)),
        ('host_operations',HOST+('operations','*'),P+('host_link','*'),('namespace','host','declaration','admission','addition')),
        ('bootstrap_operations',('witness','operations','*'),P+('bootstrap','*'),('namespace','scope','query','policy','pins','group'))):
        fields = tuple(f for f in operation_fields if f != 'kind') if name == 'bootstrap_operations' else operation_fields
        add(name,observation,history,fields+extra)
    add('bootstrap_producer_source',('witness','operations','*'),P+('producer_creation',),('parent','name'))
    add('binding_operation',BINDING+('observation',),P+('producer_binding',),
        tuple(f for f in operation_fields if f != 'kind')+('parent','group','name','data','query','policy','pins'))
    add('producer_operation',QUARANTINE+('producer',),P+('producer_creation',),
        ('request','parent','group','name','data','query','birth','requested_at','deadline','verified_at',
         ('original_pid','birth.pid'),('original_start','birth.start')))
    add('binding_original_group',BINDING,P+('producer_creation',),(('original_group','group'),))

    for name,observation,index in (
        ('host_intent',HOST+('own_intent_polling',),75),
        ('bootstrap_query_intent',('witness','own_query_intent_polling'),87),
        ('bootstrap_intent',('witness','own_intent_polling'),90)):
        add(name,observation,P+('writers',index),('pid','start'))
    add('quarantine_intent',QUARANTINE+('own_intent_polling',),P+('writers',42),
        (('original_writer.pid','pid'),('original_writer.start','start'),
         ('deadline','io_deadline'),'verified_at','actual_wait_status'))

    original_jobs = [P+('attachment','birth'),P+('fresh_transport','birth'),P+('fresh_transport','mount','birth')]
    original_jobs += [P+('wireguard',i,'birth') for i in range(5)]
    original_jobs += [P+('netfilter',i,'birth') for i in range(6)]
    original_jobs += [P+('producer_creation','birth')]
    suffix_jobs = [P+('producer_binding','birth')]+[P+('host_link',i,'birth') for i in range(4)]
    for prefix,jobs in ((ASSEMBLY,original_jobs),(('witness','handoff'),suffix_jobs)):
        for i,source in enumerate(jobs):
            add('retired_job:'+'.'.join(prefix)+':'+str(i),prefix+('resources',i),source,
                (('original_pid','pid'),('original_start','start')))
        add('reservation_owner:'+'.'.join(prefix),prefix+('reservation',),P,
            (('owner_epoch','canonical_owner_epoch'),'member'))

    # I10: attachment/movement.rs:824-835. Use the original query result,
    # not another retained copy of the moved result.
    add('original_wireguard_move',P+('wireguard',4,'result'),P+('wireguard',2,'result'),
        ('link.name','link.alias','wireguard.public_key','wireguard.peers'))

    add('host_admission_history',HOST+('admission',),P+('host_link',0),
        ('declaration',('namespace','host'),(('requested_at',),('admission',0)),
         (('deadline',),('admission',1)),(('accepted_at',),('admission',2))))
    add('host_baseline',HOST+('admission',),('rows','secret_host_baseline',0,'declaration'),
        (('declared_baseline','baseline'),('namespace','host_namespace')))
    add('host_inventory',HOST+('operations',3,'host_observation'),HOST+('admission','declared_baseline'),
        ('namespace','addresses','routes','rules'))
    # The added link is separately checked against the original host result.
    add('host_inventory_links',HOST+('operations',3,'host_observation'),None,('links',),'root',('retained_success',))
    add('wan_declaration',QUARANTINE+('wan',),('rows','secret_quarantine_host',0,'declaration'),
        (('host_namespace','host_namespace'),('name','wan.name'),('index','wan.index'),('address','wan.address')))
    add('wan_observation_window',QUARANTINE+('wan',),P+('netfilter',1),('requested_at','deadline'))
    add('foreign_capacity_parent',ASSEMBLY+('foreign_eligibility',),P+('wireguard',0,'birth'),
        (('eligible_original_pid','pid'),('eligible_original_start','start')))
    add('foreign_capacity_observation',ASSEMBLY+('foreign_eligibility',),None,
        ('original_pid','original_start','requested_at','deadline','verified_at'),
        'root',('recorded_emitters','monotonic_deadlines'))
    return tuple(registry)


BINDING_REGISTRY = make_binding_registry()


def schema_nodes(value, spec='BootstrapWitness', path=('witness',)):
    """Walk declared schema edges only; unknown observation children stay uncovered."""
    if value is None:
        return
    if '|' in spec:
        choices = [s for s in alternatives(spec) if s in SCHEMAS and type(value) is dict]
        if choices:
            spec = min(choices,key=lambda s: len(set(value).symmetric_difference(SCHEMAS[s])))
    if spec in SCHEMAS and type(value) is dict:
        yield path, value
        for key,child_spec in SCHEMAS[spec].items():
            if key in value:
                yield from schema_nodes(value[key],child_spec,path+(key,))
    elif spec.startswith('list(') or spec == 'queries3':
        child_spec = 'InspectionHistory|null' if spec == 'queries3' else spec[5:-1]
        if type(value) is list:
            for i,child in enumerate(value):
                yield from schema_nodes(child,child_spec,path+(i,))


def at_path(root, path):
    for key in path:
        root = root[key]
    return root


def binding_instances(root, pattern, path=(), captures=()):
    if not pattern:
        yield path,captures,root
    elif pattern[0] == '*':
        require(type(root) is list, 'binding wildcard requires array')
        for i,item in enumerate(root):
            yield from binding_instances(item,pattern[1:],path+(i,),captures+(i,))
    else:
        key = pattern[0]
        yield from binding_instances(root[key],pattern[1:],path+(key,),captures)


def bind_observations(w, rows):
    """The single comparison engine for the complete declarative registry."""
    root = dict(witness=w,rows=rows,expected={'initial_query': {'kind': 'Initial'}})
    for entry in BINDING_REGISTRY:
        for path,captures,observation in binding_instances(root,entry['observation']):
            if entry['mode'] == 'root':
                continue  # explicitly named canonical evidence; guards run in validate
            indices = iter(captures)
            source_path = tuple(next(indices) if key == '*' else key for key in entry['canonical'])
            source = at_path(root,source_path)
            for left,right in entry['fields']:
                actual,expected = at_path(observation,left),at_path(source,right)
                if entry['mode'] == 'projection':
                    if actual is None:
                        continue
                    if left == ('bootstrap_queries',):
                        require(all(q is None or q == expected[i] for i,q in enumerate(actual)),entry['name']+': queries')
                        continue
                    if type(actual) is list:
                        expected = expected[:len(actual)]
                require(actual == expected, entry['name']+': '+repr(path+left)+' binds '+repr(source_path+right))
    coverage = binding_coverage(w)
    require(not coverage['uncovered'], 'unregistered observation objects: '+repr(coverage['uncovered']))


OBSERVATION_KEYS = frozenset(('pid','start','dev','ino','deadline','birth','original_pid',
                              'original_start','process_start','io_deadline','parent_deadline'))


def binding_coverage(w):
    # Coverage is established by explicit compared fields, not a blanket parent
    # exemption or object-shape whitelist. schema_nodes refuses unknown edges.
    nodes = dict(schema_nodes(w))
    prefixes = set()
    for entry in BINDING_REGISTRY:
        for path,_,_ in binding_instances(dict(witness=w),entry['observation']):
            for left,_ in entry['fields']:
                prefixes.add(path+left)
    observations = []
    uncovered = []
    def walk(value,path):
        if type(value) is dict:
            keys = OBSERVATION_KEYS.intersection(value)
            if keys:
                observations.append(path)
                fields = [path+(key,) for key in keys]
                if path not in nodes or any(not any(field[:i] in prefixes for i in range(1,len(field)+1))
                                            for field in fields):
                    uncovered.append(path)
            for key,child in value.items():
                walk(child,path+(key,))
        elif type(value) is list:
            for i,child in enumerate(value):
                walk(child,path+(i,))
    walk(w,('witness',))
    return dict(observations=len(observations),uncovered=uncovered)


def intent_success(intent, p, index, negatives, held=2):
    writer = p['writers'][index]
    identity = intent.get('original_writer', intent)
    require(identity['index'] == index and identity['pid'] == writer['pid']
            and identity['start'] == writer['start'] and writer['actual_wait_status'] == 0,
            'original held intent writer identity/status')
    require(intent['queued_polls'] == 1 and intent['held_pending_polls'] >= held
            and intent['negative_checks'] == negatives, 'original intent poll/negative counts')
    if 'released' in intent:
        require(intent['released'] is True and intent['held_pending_polls'] == held,
                'original intent release/held count')
    else:
        require(intent['actual_wait_status'] == 0 and intent['verified_at'] == writer['verified_at']
                and intent['deadline'] == writer['io_deadline'] == writer['parent_deadline'],
                'original quarantine intent receipt')


def preparation_idle(p):
    for key in ('native_children_reaped', 'service_reserved', 'entry_links_absent',
                'entry_attempt_absent', 'entry_terminal_absent', 'owner_host_anchor_present',
                'canonical_result_present'):
        require(p[key] is True, 'successful preparation.' + key)
    for key in ('member_native_jobs_collected', 'canonical_pending', 'mutation_fenced', 'base_network_absent'):
        require(p[key] is False, 'successful preparation.' + key)
    require(p['entry_phase'] == 'creating' and p['entry_producer_absent'] is (p['entry_producer'] is None),
            'successful creating entry/publication discriminator')
    for key in ('pending_bootstrap', 'pending_host_link', 'pending_producer_binding',
                'pending_producer_creation', 'pending_wireguard'):
        require(p[key] is None, 'successful preparation.' + key)


def original_operation(op, history, borrowed=None):
    same_fields(op, history, [key for key in ('kind', 'scope', 'namespace', 'host', 'data', 'parent',
                'name', 'group', 'request', 'query', 'policy', 'pins', 'declaration', 'admission',
                'addition', 'birth', 'requested_at', 'deadline', 'result') if key in op and key in history],
                'original operation/history')
    require(op['accepted_at'] == history['verified_at'] and op['actual_wait_status'] == 0
            and op['original_pid'] == history['birth']['pid']
            and op['original_start'] == history['birth']['start']
            and op['native_job_state'] == 'born', 'original operation identity/status/ack')
    for key in ('acknowledged', 'native_born', 'context_retained', 'eof', 'durable_birth_released',
                'complete_native_registration', 'full_descriptor_registration', 'original_registration_slots_verified'):
        if key in op:
            require(op[key] is True, 'original completed operation.' + key)
    if borrowed is not None:
        require(op['borrowed_registration_count'] == borrowed, 'original borrowed registrations')


def retained_success(w):
    host = w['host_addition']
    binding = host['producer_binding']
    assembly = binding['assembly']
    quarantine = assembly['quarantine']
    movement = quarantine['movement']
    provision = movement['provision']
    attachment = provision['attachment']
    stages = [host, binding, assembly, quarantine, movement, provision]
    counts = [87, 75, 69, 69, 42, 33]
    for stage, count in zip(stages, counts):
        require(stage['schema'] == 1 and stage['fault'] == 0 and stage['parent_pristine'] is True
                and stage['continued_original_context'] is True, 'retained successful continuation schema/fault/parent')
        # These emitters return their continuing owner before their drop branch.
        for key in stage:
            if key.endswith('_retained_after_drop'):
                require(stage[key] is False, 'retained continuation precedes drop: ' + key)
        for key in ('failed_constructor', 'failure_retry', 'retained_result_writer', 'charges_after_drop'):
            if key in stage:
                require(stage[key] is None, 'retained continuation.' + key)
        for key in ('result_writer_held', 'held_real_result_writer', 'unacknowledged_native_result_retained',
                    'unacknowledged_host_addition_retained', 'unacknowledged_observation_retained'):
            if key in stage:
                require(stage[key] is False, 'retained success.' + key)
        preparation_idle(stage['preparation'])
        require(stage['preparation']['bootstrap'] == [] and stage['preparation']['bootstrap_queries'] == [None]*3,
                'retained stage precedes Bootstrap')
        require(len(stage['preparation']['writers']) == count, 'retained writer count')
    for later, earlier, count, fields in [
        (host, binding, 75, ('wireguard','netfilter','producer_creation','producer_binding',
          'producer_binding_query','producer_query','quarantine_query','movement_query','inspection','attachment','fresh_transport')),
        (binding, assembly, 69, ('member','requested_at','deadline','birth','base_network_absent','base_network',
          'data_network','transport_network','inspection','attachment','fresh_transport','wireguard',
          'movement_query','netfilter','quarantine_query','producer_query','producer_creation')),
        (quarantine, movement, 42, ('member','canonical_owner_epoch','inspection','attachment','fresh_transport',
          'wireguard','movement_query','base_network','data_network','transport_network')),
        (movement, provision, 33, ('canonical_owner_epoch','inspection','attachment','fresh_transport',
          'base_network','data_network','transport_network')),
        (provision, attachment, 17, ('canonical_owner_epoch','member','base_network','data_network','inspection','attachment'))]:
        lp, ep = later['preparation'], earlier['preparation']
        require(lp['writers'][:count] == ep['writers'], 'retained original writer prefix')
        same_fields(lp, ep, fields, 'retained preparation prefix')
    require(assembly['preparation'] == quarantine['preparation'], 'assembly unchanged preparation')
    require(movement['preparation']['wireguard'][:3] == provision['preparation']['wireguard']
            and movement['operations'][:3] == provision['operations'], 'movement original provision operations')
    require(host['canonical_negative_checks'] == 20 and host['charges_before'] == [1,1]
            and host['charges_before_drop'] == [5,5], 'host schema oracle and charges')
    intent_success(host['own_intent_polling'], host['preparation'], 75, 12)
    require(binding['charges_before'] == [0,0] and binding['charges_before_drop'] == [1,1]
            and binding['canonical_negative_checks'] == 25 and binding['canonical_producer_published'] is True and binding['same_original_source'] is True,
            'producer binding success publication/charges')
    require(binding['original_group'] == binding['preparation']['producer_creation']['group'], 'original producer group')
    require(assembly['charges_before'] == [15,11] and assembly['charges_after'] == [0,0]
            and assembly['retired_original_jobs'] == 15 and assembly['handoff_complete'] is True
            and assembly['duplicate_reservation_refused'] is False and assembly['repeat_retirement_refused'] is True
            and assembly['lower_repeat_retirement_refused'] is True and assembly['fence_blocked_next_transfer'] is False
            and assembly['duplicate_reservation_counts'] is None and assembly['fence_counts'] is None,
            'original assembly retirement success')
    r = assembly['reservation']
    require(r['complete'] is True and r['original_jobs'] == 15 and r['member_transfer_pending'] is False
            and r['global_assemblies_reserved'] == 1 and r['global_assembly_limit'] == 128
            and r['global_transferred_ticket_limit'] == 2560 and r['member'] == w['preparation']['member'],
            'original assembly reservation')
    intent_success(quarantine['own_intent_polling'], quarantine['preparation'], 42, 12)
    for stage, flags in [(host, ('isolated_pair_creation_observed','single_down_host_addition_observed',
                                  'canonical_host_addition_acknowledged','host_addresses_routes_rules_preserved')),
                         (quarantine, ('same_service_retained','initial_quarantine_only',
                           'initial_quarantine_installation_observed_all_scopes','producer_group_creation_observed')),
                         (movement, ('same_service_retained','data_move_completed','move_borrows_both_original_pairs',
                           'original_query_parent_readback_advanced','wireguard_down_only')),
                         (provision, ('same_service_retained','transport_distinct_from_host_and_data',
                           'original_socket_registrations_borrowed','wireguard_down_only'))]:
        for flag in flags:
            require(stage[flag] is True, 'retained success.' + flag)
    for stage, key in [(binding,'host_network_links_or_routes_created'), (quarantine,'host_network_links_or_routes_created'),
                       (movement,'host_resources_created'), (provision,'host_resources_created'),
                       (assembly,'producer_operational_publication'), (quarantine,'producer_operational_publication')]:
        require(stage[key] is False, 'retained boundary.' + key)
    for stage, writer_index, query in [(binding,74,binding['query']), (quarantine,68,quarantine['producer_query']),
                                     (movement,41,movement['movement_query'])]:
        require(stage['preparation']['writers'][writer_index]['verified_at'] <= stage['final_process_verified_at']
                < query['deadline'], 'retained final process verification window')
    require(host['admission']['two_original_reads_verified'] is True
            and host['admission']['same_generation_owner_retained'] is True
            and host['admission']['polls'] > 0, 'host original baseline admission')
    admission = host['admission']
    baseline = admission['declared_baseline']
    final = host['operations'][3]['host_observation']
    require(final is not None and final['namespace'] == baseline['namespace'], 'host inventory namespace')
    same_fields(final, baseline, ('addresses','routes','rules'), 'host preserved inventory')
    added = host['operations'][3]['result']['host']
    require(len(final['links']) == len(baseline['links'])+1
            and final['links'].count(added) == 1 and all(final['links'].count(link) == 1 for link in baseline['links']),
            'host exactly one original down addition')
    for i,op in enumerate(host['operations']):
        require(op['admission'] == [admission['requested_at'],admission['deadline'],admission['accepted_at']]
                and op['declaration'] == admission['declaration']
                and (op['host_observation'] is not None) == (i == 3), 'host original admission/observation chain')
    hp = host['preparation']
    require(len(host['operations']) == len(hp['host_link']) == 4, 'four host operations')
    for index, (op, h) in enumerate(zip(host['operations'], hp['host_link'])):
        original_operation(op, h, [0,2,0,4][index])
        if index in (1,3):
            require(op['postcompletion_inventory_preserved'] is True and op['postcompletion_inventory_polls'] >= 2,
                    'host postcompletion inventories')
        for writer in hp['writers'][75+index*3:78+index*3]:
            require(writer['io_deadline'] == writer['parent_deadline'] == h['deadline'], 'host writer window')
    require([x['phase'] for x in hp['writers'][75:]] == ['host_link_'+s for _ in range(4) for s in ('intent','birth','result')],
            'host writer phases')
    require(len(quarantine['operations']) == 6, 'six quarantine operations')
    for i, (op,h) in enumerate(zip(quarantine['operations'], quarantine['preparation']['netfilter'])):
        original_operation(op,h,0 if i % 2 == 0 else 2)
    original_operation(binding['observation'], binding['preparation']['producer_binding'], 2)
    for stage in (movement,provision):
        require(len(stage['operations']) == (5 if stage is movement else 3), 'wireguard operation count')
        for op,h in zip(stage['operations'],stage['preparation']['wireguard']):
            original_operation(op,h)
    for stage,query,key in [(binding,binding['query'],'producer_binding_query'),
                            (quarantine,quarantine['producer_query'],'producer_query'),
                            (quarantine,quarantine['quarantine_query'],'quarantine_query'),
                            (movement,movement['movement_query'],'movement_query')]:
        same_fields(query, stage['preparation'][key], ('kind','birth','facts','requested_at','deadline','verified_at'),
                    'retained original query/history')


def recorded_emitters(w, rows):
    # Additional success evidence from the retained constructor/result builders.
    shapes = {name:set(SCHEMAS[name]) for name in ('Query','Resource','MountWitness',
              'TransportWitness','AttachmentWitness','ProducerWitness','Wan','MovementOperation')}
    gateway = rows['secret_attachment_gateway'][0]
    for path,obj in objects(w):
        shape = set(obj)
        if shape == shapes['Query']:
            require(obj['actual_wait_status'] == 0 and obj['original_peer_receipt'] is True
                    and obj['handler_identity_claimed'] is False and obj['listener_origin_pid'] == 1
                    and obj['listener_origin_uid'] == obj['listener_origin_gid'] == 0
                    and obj['facts']['pid'] == gateway['pid']
                    and obj['facts']['security'] == 'AppArmorBuiltinSeccomp', path + ': original Docker query receipt')
        elif shape == shapes['Resource']:
            lower = obj['kind'] in ('WireguardSecret','FixedNetfilter','FixedVeth')
            require(obj['actual_wait_status'] == 0 and obj['native_job_state'] == 'transferred_resources'
                    and obj['fully_retired'] is True and obj['launch_charge_retired'] is True
                    and obj['transfer_started'] is True and obj['lower_charge_required'] is lower
                    and obj['lower_charge_retired'] is (True if lower else None)
                    and obj['lower_gated_retirement_refused'] is (True if lower else None), path + ': original retired resource')
        elif shape == shapes['MountWitness']:
            require(obj['actual_wait_status'] == 0 and obj['eof'] is True
                    and obj['original_mounted_namespace_retained'] is True
                    and obj['original_placeholder_retained'] is True and obj['received_packets'] == 2
                    and obj['released_gates'] == 2, path + ': original completed mount')
        elif shape == shapes['TransportWitness']:
            require(obj['actual_wait_status'] == 0 and obj['durable_birth_released'] is True
                    and obj['eof'] is True and obj['original_source_retained'] is True,
                    path + ': original fresh transport')
        elif shape == shapes['AttachmentWitness']:
            require(obj['schema'] == 1 and obj['fault'] == 0 and obj['base_published'] is True
                    and obj['original_mount_retained'] is True and obj['parent_pristine'] is True
                    and obj['same_service_retained'] is True and obj['held_real_writer'] is False
                    and obj['whole_failed_driver_retained_after_drop'] is False
                    and obj['normal_ack_ready_preserved'] is False, path + ': successful attachment')
            p = obj['preparation']
            require(len(p['writers']) == 17 and p['transport_network'] is None, 'attachment preparation')
            require(obj['validator']['birth'] == p['birth'] and obj['validator']['actual_wait_status'] == 0,
                    'original validator birth/status')
            same_fields(obj['mount'],p['attachment'],('birth','requested_at','deadline','placeholder'),'original DATA mount')
            require(obj['mount']['original_source'] == p['attachment']['source']
                    and obj['mount']['original_directory'] == p['attachment']['directory'], 'original DATA mount identities')
            for query,key in [(obj['first_query'],'initial'),(obj['second_query'],None)]:
                history = p['inspection'][key] if key else p['inspection']
                same_fields(query,history,('birth','facts','verified_at'),'original first/second inspection')
            same_fields(obj['postmount_query'],p['attachment']['query'],('birth','facts','verified_at'), 'original postmount query')
            require(obj['inspection_requested_at'] == p['inspection']['requested_at']
                    and obj['inspection_deadline'] == p['inspection']['deadline']
                    and p['inspection']['verified_at'] <= obj['inspection_verified_at'] < obj['inspection_deadline']
                    and obj['inspection_verified_at'] <= p['attachment']['requested_at'], 'original inspection window')
        elif shape == shapes['ProducerWitness']:
            for key in ('acknowledged','context_retained','durable_birth_released','eof','full_descriptor_registration',
                        'native_born','received_original_group'):
                require(obj[key] is True, path + '.' + key)
            require(obj['operational_publication'] is False and obj['parent_death_lock_survival_claimed'] is False
                    and obj['actual_wait_status'] == 0 and obj['native_job_state'] == 'born'
                    and obj['registered_native_slots'] >= 3, 'original producer evidence')
            creation = w['preparation']['producer_creation']
            same_fields(obj,creation,('request','parent','group','name','data','query','birth','requested_at','deadline','verified_at'),
                        'original producer creation operation')
            require(obj['original_pid'] == obj['birth']['pid'] and obj['original_start'] == obj['birth']['start'],
                    'original producer native identity')
        elif shape == shapes['Wan']:
            require(obj['original_observer_retained'] is True, 'original WAN observer')
        elif shape == shapes['MovementOperation']:
            inventory = obj['kind'] not in ('sockets','data_sockets')
            require(obj['postcompletion_inventory_preserved'] is inventory
                    and (obj['postcompletion_inventory_polls'] >= 2 if inventory else obj['postcompletion_inventory_polls'] == 0),
                    'original transport postcompletion inventory')
            require(obj['borrowed_registration_count'] == (4 if obj['kind'] == 'move' else 0 if not inventory else 2)
                    and obj['registered_native_slots'] >= 3, 'original transport native registrations')
    host = w['host_addition']
    binding = host['producer_binding']
    assembly = binding['assembly']
    quarantine = assembly['quarantine']
    movement = quarantine['movement']
    provision = movement['provision']
    expected = [provision['attachment']['mount'], provision['transport_creation'], provision['transport_mount']] + movement['operations'] + quarantine['operations'] + [quarantine['producer']]
    resources = assembly['resources']
    require(len(resources) == 15 and [r['kind'] for r in resources] ==
            ['NamespaceAttachment','FreshTransport','FreshTransportMount']+['WireguardSecret']*5+['FixedNetfilter']*6+['ProducerCreation'],
            'assembly fifteen original resource kinds')
    for resource,op in zip(resources,expected):
        birth = op['birth']
        require(resource['original_pid'] == birth['pid'] and resource['original_start'] == birth['start'],
                'assembly original retired resource identity')
    f = assembly['foreign_eligibility']
    require(f['schema'] == 1 and 1 < f['original_pid'] <= 2**31-1 and f['original_start'] > 0 and f['actual_wait_status'] == 0 and f['eof'] is True
            and f['eligible_foreign_refused'] is True and f['parent_still_eligible'] is True
            and f['canonical_operation'] is False and f['successful_capacity_transfer_proven'] is False
            and f['parent_counts_before'] == f['parent_counts_after'] == [15,11]
            and f['eligible_original_pid'] == resources[3]['original_pid']
            and f['eligible_original_start'] == resources[3]['original_start'], 'foreign capacity refusal metadata')
    # The original query's accepted readback advances only the route sequence.
    sequences = movement['operations'][2]['query_sequences']
    require(sequences[1][0] > sequences[0][0] and sequences[0][1] == sequences[1][1], 'original query parent readback')
    for op in host['operations']:
        require(op['registered_native_slots'] >= 3, 'host native registration minimum')
    require(binding['observation']['registered_native_slots'] >= 9, 'binding native registration minimum')
    # These are immutable recorded fstat modes. UID/GID, FD access modes and
    # fstatfs custody are not present in the witness and cannot be reconstructed.
    for op in w['operations']:
        require(all((mode & 0o022) == 0 and (mode & 0o170000) == (0o100000 if 2 <= i < 6 else 0o040000)
                    for i,(_,_,mode) in enumerate(op['pins'])), 'Bootstrap pin file types and modes')


def allocation_contract(w,rows):
    """Public AllocationRecord::validate, including every nonprimary exit."""
    descriptor = rows['secret_attachment_descriptor'][0]
    allocation = descriptor['allocation']
    deployment = descriptor['deployment_id']
    def label(value):
        require(bool(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?',value)) and len(value) <= 32,
                'native allocation bounded ASCII label')
    label(deployment)
    require(allocation['deployment_id'] == deployment and allocation['schema_version'] == 2
            and allocation['generation'] > 0 and 0 < len(allocation['exits']) <= CONTRACT['success_rules']['max_exits'],
            'native public allocation deployment/schema/generation/exits')
    resources = {k:set() for k in ('ids','namespaces','interfaces','tables','subnets')}
    states = []
    def unique(category,value):
        require(value not in resources[category],'native allocation duplicate '+category)
        resources[category].add(value)
    for exit in allocation['exits']:
        identity = exit['exit_id'];label(identity);unique('ids',identity)
        state = exit['state_dir']
        parts = state.split('/')[1:]
        require(state.startswith('/') and state != '/' and '\0' not in state
                and all(part not in ('','.','..') for part in parts),'native allocation absolute nonroot state path')
        require(not any(parts[:len(old)] == old or old[:len(parts)] == parts for old in states),
                'native allocation overlapping state paths')
        states.append(parts)
        h = CONTRACT['success_rules']['allocation_hash_seed']
        for byte in deployment.encode()+b'\0'+identity.encode():
            h = ((h ^ byte)*CONTRACT['success_rules']['allocation_hash_prime']) & (2**64-1)
        short,full,slot = f'{h & 0xffffffffffff:012x}',f'{h:016x}',h & 0xffff
        expected = dict(exit_id=identity,mode=exit['mode'],state_dir=state,
                        data_namespace='vr-data-'+full,transport_namespace='vr-trans-'+full,
                        nft_table='vr_'+full,host_interface='vh'+short,data_interface='vd'+short,
                        wireguard_interface='wg'+short if exit['mode']=='mullvad' else None,
                        transport_subnet=f'10.{200+(slot >> 14)}.{(slot >> 6)&255}.{(slot & 63)*4}/30')
        require(exit == expected,'native allocation deterministic original resource names/subnet')
        for key in ('data_namespace','transport_namespace'):
            unique('namespaces',exit[key])
        for key in ('host_interface','data_interface','wireguard_interface'):
            if exit[key] is not None:
                require(len(exit[key]) <= 15,'native allocation interface name length')
                unique('interfaces',exit[key])
        unique('tables',exit['nft_table'])
        # Every generated subnet is a /30 in the fixed pool. Distinct slots
        # cannot overlap, so exact /30 equality is the overlap test here.
        unique('subnets',exit['transport_subnet'])
    def ordered(value,schema):
        names = sorted(SCHEMAS[schema],key=lambda key:CONTRACT['field_sources'][schema+'.'+key]['line'])
        return {key:([ordered(e,'AllocationExit') for e in value[key]] if key=='exits' else value[key]) for key in names}
    digest = hashlib.sha256(json.dumps(ordered(allocation,'Allocation'),ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
    require(digest == descriptor['allocation_digest'],'native canonical serde allocation digest')


def contract_success(w,rows):
    """Serialized native-success guards plus original plan/journal prerequisites."""
    p = w['preparation']
    descriptor = rows['secret_attachment_descriptor'][0]
    allocation = descriptor['allocation']
    primary = next(e for e in allocation['exits'] if e['exit_id'] == p['member'])
    inputs = rows['secret_attachment_input'][0]
    profile = next(e for e in inputs['profiles'] if e['member'] == p['member'])
    rules = CONTRACT['success_rules']
    alias = f"vprouter-v2:{descriptor['deployment_id']}:{allocation['generation']}:{primary['exit_id']}"
    public = rules['public_profile']
    # The profile constants are extracted from the retained guest whose bytes
    # are bound by record.guest_sha256 in frozen_bindings.
    def link_guards(link,name,kind):
        require(link['name'] == name and link['kind'] == kind and link['alias'] == alias,
                'native result original allocated name/kind/ownership alias')
        for key,expected in rules['network_link_fixed'].items():
            require(link[key] == expected,'native Link success guard: '+key)
    for history in p['wireguard']:
        result = history['result']
        if result['link'] is None:
            continue
        link,device = result['link'],result['wireguard']
        link_guards(link,primary['wireguard_interface'],'wireguard')
        require(device is not None and device['index'] == link['index']
                and device['name'] == link['name']
                and device['public_key'] == profile['device_public_key'],
                'native WG original Link index/name and recorded public input key')
        require(len(device['peers']) == 1,'native WG exactly one planned peer')
        peer = device['peers'][0]
        require(peer['public_key'] == public['PublicKey'] and peer['endpoint'] == public['Endpoint']
                and peer['allowed_ips'] == [['0.0.0.0',0]],'native WG planned peer/endpoint/default route')
    # Query must retain the complete original provision Link, as well as its
    # original public plan. Moving can change Link index but not its plan.
    require(p['wireguard'][1]['result']['link'] == p['wireguard'][2]['result']['link'],
            'WG query original provision Link continuity')
    for history in p['host_link']:
        result = history['result']
        if result['host'] is not None:
            link_guards(result['host'],primary['host_interface'],'veth')
            link_guards(result['peer'],primary['data_interface'],'veth')
        if history['addition'] is not None:
            require(any(history['addition'][0]),'nonzero original HostAdditionPlan digest')
    wan = w['host_addition']['producer_binding']['assembly']['quarantine']['wan']
    host_policy = p['netfilter'][1]
    require(wan['requested_at'] == host_policy['requested_at'] and wan['deadline'] == host_policy['deadline']
            and wan['verified_at'] <= host_policy['birth']['born_at'],
            'WAN original HOST InitialQuarantine request window and prerequisite completion')
    require(p['attachment']['directory'] == p['fresh_transport']['directory'] == p['fresh_transport']['mount']['directory'],
            'DATA and TRANSPORT original journal directory')
    require(w['host_addition']['producer_binding']['assembly']['global_child_capacity_limit'] == rules['assembly_capacity'],
            'assembly emitter fixed global child capacity')


def writer_histories(w):
    p = w['preparation']
    expected = []
    def append(phases, end):
        expected.extend((phase,end) for phase in phases)
    append(('intent','birth','result'),p['deadline'])
    append(('inspection_intent','inspection_birth','inspection_result')*2,p['inspection']['deadline'])
    append(('attachment_intent','attachment_birth','attachment_placeholder','attachment_mounted',
            'attachment_query_intent','attachment_query_birth','attachment_query_result','attachment_primary'),p['attachment']['deadline'])
    append(('transport_intent','transport_birth','transport_source'),p['fresh_transport']['deadline'])
    append(('transport_mount_intent','transport_mount_birth','transport_mount_placeholder','transport_mount_publication'),p['fresh_transport']['mount']['deadline'])
    for h in p['wireguard'][:3]:
        append(('wireguard_intent','wireguard_birth','wireguard_result'),h['deadline'])
    append(('wireguard_intent','wireguard_birth','wireguard_result'),p['wireguard'][3]['deadline'])
    append(('movement_query_intent','movement_query_birth','movement_query_result'),p['movement_query']['deadline'])
    append(('wireguard_intent','wireguard_birth','wireguard_result'),p['wireguard'][4]['deadline'])
    for h in p['netfilter'][:5]:
        append(('netfilter_intent','netfilter_birth','netfilter_result'),h['deadline'])
    append(('quarantine_query_intent','quarantine_query_birth','quarantine_query_result'),p['quarantine_query']['deadline'])
    append(('netfilter_intent','netfilter_birth','netfilter_result'),p['netfilter'][5]['deadline'])
    append(('producer_query_intent','producer_query_birth','producer_query_result'),p['producer_query']['deadline'])
    append(('producer_intent','producer_birth','producer_result'),p['producer_creation']['deadline'])
    append(('producer_binding_query_intent','producer_binding_query_birth','producer_binding_query_result'),p['producer_binding_query']['deadline'])
    append(('producer_binding_intent','producer_binding_birth','producer_binding_result'),p['producer_binding']['deadline'])
    for h in p['host_link']:
        append(('host_link_intent','host_link_birth','host_link_result'),h['deadline'])
    for h in p['bootstrap']:
        append(tuple('bootstrap_'+h['scope']+'_'+s for s in ('query_intent','query_birth','query_result','intent','birth','result')),h['deadline'])
    require(len(expected) == len(p['writers']) == 105, 'complete writer schedule')
    for writer,(phase,end) in zip(p['writers'],expected):
        require(writer['phase'] == phase and writer['actual_wait_status'] == 0
                and writer['io_deadline'] == writer['parent_deadline'] == end
                and end-2 <= writer['queued_at'] <= writer['verified_at'] < end
                and writer['pid'] > 1 and writer['start'] > 0, 'original writer phase/window/status/identity')
    for path,obj in objects(w):
        if 'canonical_owner_epoch' in obj:
            require(obj['writers'] == p['writers'][:len(obj['writers'])], path + ': original writer prefix')


def controller_consistency(w, record, rows):
    c = rows['secret_attachment_controller'][0]
    descriptor, gateway, inputs = (rows[key][0] for key in (
        'secret_attachment_descriptor', 'secret_attachment_gateway', 'secret_attachment_input'))
    primary = next(e for e in descriptor['allocation']['exits'] if e['exit_id'] == descriptor['primary'])
    require(c['harness_exit_code'] == record['exit_code'] == rows['secret_attachment_owner_launcher'][0]['exit_code'] == 0
            and rows['secret_attachment_build_exit'] == [0]
            and rows['case'] == [dict(case='actual_original_three_scope_bootstrap_after_exact_twenty_handoff', result='PASS')], 'build/harness/launcher/case status')
    for key in ('owner_unit_absent', 'host_single_down_link_added', 'host_addresses_routes_rules_preserved',
                'host_stable_neighbors_preserved', 'inert_gateway_retained', 'original_gateway_native_identity_unchanged',
                'synthetic_only', 'native_transport_operations_requested', 'canonical_and_mount_resources_retained'):
        require(c[key] is True, 'controller.' + key)
    require(c['host_links_and_stable_routes_unchanged'] is False
            and c['host_links_and_stable_routes_unchanged'] is (not c['host_single_down_link_added']),
            'controller: unchanged=false is required by single down link addition')
    require(c['host_allowed_index'] == descriptor['planned_host_link_index'] == w['host_addition']['planned_host_link_index']
            and c['host_allowed_name'] == primary['host_interface'], 'controller original allowed link index/name')
    require(gateway['inert'] is True and gateway['provider_state_mounted'] is False and gateway['mounts'] == [],
            'gateway inert / no mounts / no provider state')
    origin = w['preparation']['attachment']['origin']
    require(origin['container'] == gateway['container_id'] and origin['process_start'] == gateway['start']
            and origin['network'] == dict(zip(('dev', 'ino'), gateway['source_namespace']))
            and w['preparation']['attachment']['source'] == origin['network'], 'gateway original native identity')
    require(w['preparation']['data_network'] == origin['network']
            and gateway['source_namespace'] != gateway['host_network_namespace'], 'gateway data namespace distinct from host')
    require(inputs['nonce'] == descriptor['nonce'] == rows['owner_probe'][0]['nonce']
            and descriptor['primary'] == w['preparation']['member'] == inputs['profiles'][0]['member'], 'input nonce/member')
    require(inputs['synthetic_only'] is True and inputs['private_bytes_in_argv_environment_or_configuration'] is False
            and inputs['keys_created_outside_rust_parent'] is True, 'synthetic input boundary')
    env = rows['secret_attachment_environment'][0]
    require(env['schema'] == 1 and env['sampled_during_native_operation'] is False and env['whole_vm_only'] is True
            and 0 <= env['before']['started_at'] <= env['before']['finished_at'] <= w['preparation']['requested_at']
            <= w['final_process_verified_at'] <= env['after']['started_at'] <= env['after']['finished_at'],
            'environment: before/Bootstrap/after monotonic order and observational scope')
    host = w['host_addition']
    require(host['single_down_host_addition_observed'] is True and host['isolated_pair_creation_observed'] is True
            and host['canonical_host_addition_acknowledged'] is True
            and host['host_addresses_routes_rules_preserved'] is True, 'host addition success observations')
    final_link = w['preparation']['host_link'][3]
    require(final_link['kind'] == 'move' and final_link['birth'] is not None
            and final_link['verified_at'] is not None and final_link['result'] is not None
            and final_link['addition'] is not None and final_link['addition'][1] == c['host_allowed_index'],
            'canonical completed original host move/addition')
    require(final_link['result'] == host['operations'][3]['result']
            and final_link['result']['host']['index'] == c['host_allowed_index'],
            'canonical host move / recorded native operation result')
    for path, obj in objects(w):
        if 'host' in obj and type(obj['host']) is dict and 'index' in obj['host']:
            link = obj['host']
            if link['index'] == c['host_allowed_index']:
                require(link['name'] == c['host_allowed_name'] and link['up'] is False and link['kind'] == 'veth',
                        path + ': original down host veth')
    admissions = rows['secret_attachment_admission']
    require(admissions[0]['content']['image_id'] == gateway['image_id']
            and admissions[0]['content']['program_manifest_sha256'] == gateway['program_manifest_sha256'] == descriptor['program_manifest_sha256']
            and admissions[1]['content']['artifact_sha256'] == record['artifact_sha256']
            and [admissions[1]['content']['network_dev'], admissions[1]['content']['network_ino']] == gateway['host_network_namespace'],
            'admission image/artifact/host namespace')


def baseline_consistency(w, record, rows):
    meta = rows['secret_host_baseline'][0]
    template = strict_json((ROOT / CANDIDATE.parent / 'authored-host-baseline-debian-clean-x86_64.json').read_bytes())
    descriptor = rows['secret_attachment_descriptor'][0]
    namespace = dict(zip(('dev', 'ino'), rows['secret_attachment_gateway'][0]['host_network_namespace']))
    expected = dict(schema_version=1, deployment_id=descriptor['deployment_id'], generation=descriptor['allocation']['generation'],
                    allocation_digest=descriptor['allocation_digest'], host_namespace=namespace, baseline=template['baseline'])
    require(meta['declaration'] == expected and meta['sha256'] == hashlib.sha256(canonical(expected)).hexdigest()
            and meta['bytes'] == len(canonical(expected)), 'baseline declaration/digest/size')
    for key, record_key in [('builder_sha256', 'baseline_declaration_builder_sha256'),
                            ('template_sha256', 'host_baseline_template_sha256'), ('review_sha256', 'baseline_reconciliation_sha256')]:
        require(meta[key] == record[record_key], 'baseline.' + key)
    require(meta['template_baseline_sha256'] == template['baseline_sha256'] == hashlib.sha256(canonical(template['baseline'])).hexdigest()
            and w['host_addition']['admission']['declared_baseline'] == template['baseline']
            and w['host_addition']['admission']['namespace'] == namespace
            and w['host_addition']['admission']['declaration'] == list(bytes.fromhex(meta['sha256']))
            and meta['authored_public_input_only'] is meta['projection_matched_authored_shape'] is True,
            'host admission matches frozen authored baseline')
    host = rows['secret_quarantine_host'][0]
    require(host['bytes'] == len(canonical(host['declaration']))
            and host['sha256'] == hashlib.sha256(canonical(host['declaration'])).hexdigest()
            and host['builder_sha256'] == record['host_declaration_builder_sha256']
            and host['declaration']['host_namespace'] == namespace, 'quarantine host declaration binding')
    declaration = host['declaration']
    require(declaration['schema_version'] == 1 and declaration['deployment_id'] == descriptor['deployment_id']
            and declaration['generation'] == descriptor['allocation']['generation']
            and declaration['member'] == descriptor['primary']
            and declaration['allocation_digest'] == descriptor['allocation_digest'], 'original quarantine host allocation')
    digest = list(bytes.fromhex(host['sha256']))
    for path,obj in objects(w):
        if 'host_declaration' in obj:
            require(obj['host_declaration'] == digest, path + ': original quarantine host declaration')
    wan = w['host_addition']['producer_binding']['assembly']['quarantine']['wan']
    same_fields(wan,declaration['wan'],('name','index','address'),'original declared WAN')
    require(wan['host_namespace'] == namespace and wan['declaration_digest'] == digest, 'original WAN declaration/namespace')


def validate(raw_path):
    receipt = dict(schema=1, validator_revision=5, run=410, raw_record=str(raw_path), verdict='FAIL', checks=[],
                   full_bootstrap_witness_validation='FAIL', runtime_acceptance=False,
                   contract_sha256=CONTRACT_SHA256,guard_counts=GUARD_COUNTS,
                   frozen_helper_scope='historical retained run410 copies for fresh-baseline.py and phase3-readonly-preflight.py; no current helper/lab readiness',
                   release_ready=False, does_not_prove=LIMITS,
                   validation_scope='offline recorded run410 successful witness consistency; no live custody',
                   supersedes=['target/run410-evidence/witness-validation.json',
                               'target/run410-evidence/witness-validation-r2.json',
                               'target/run410-evidence/witness-validation-r3.json',
                               'target/run410-evidence/witness-validation-r4.json'])

    def check(name, references, function):
        row = dict(name=name, status='PASS', references=references)
        try:
            result = function()
        except (ValueError, KeyError, TypeError, IndexError, OSError, StopIteration, OverflowError, RecursionError) as error:
            row.update(status='FAIL', error=type(error).__name__ + ': ' + str(error))
            result = None
        receipt['checks'].append(row)
        return result

    def read_record():
        raw = Path(raw_path).read_bytes()
        require(0 < len(raw) < 8*1024*1024, 'raw record size bound')
        receipt['raw_record_sha256'] = hashlib.sha256(raw).hexdigest()
        return strict_json(raw)

    record = check('strict_record_json', ['raw JSON: no duplicate keys or nonfinite numbers'], read_record)
    if record is None:
        return receipt
    check('typed_record', ['raw record: closed run410 envelope'], lambda: typed(record, 'RunRecord', 'record'))
    parsed = check('stdout_rows', ['record.stdout lines 1-14: closed ordered rows, one witness'], lambda: stdout_rows(record))
    if parsed is not None:
        w, rows, references = parsed
        receipt['stdout_line_references'] = references
        check('typed_witness', ['record.stdout line 13 LAB_SECRET_BOOTSTRAP: closed recursive types'], lambda: typed(w, 'BootstrapWitness', 'witness'))
        if receipt['checks'][-1]['status'] == 'FAIL':
            return receipt
        check('frozen_bindings', ['record.source_binding, *_sha256, run_reservation', str(RESERVATION), str(CANDIDATE)], lambda: frozen_bindings(record))
        for name, refs, fn in [
            ('bootstrap_success', ['stdout:13 schema/fault/nulls/acknowledgments/retention/parent_pristine/39 negatives; intent index/PID/start at writers 87/90'], lambda: bootstrap_success(w, record)),
            ('preparation_success', ['stdout:13 preparation success guards/entry_producer/87-writer prefix/16 retained fields', 'attachment/operational/bootstrap.rs:1028-1069'], lambda: preparation_success(w)),
            ('retained_success', ['stdout:13 retained successful emitter continuations; host intent writer75/oracle20/operations'], lambda: retained_success(w)),
            ('contract_guards', ['every source guard has an exact implemented/offline disposition'], contract_guards),
            ('allocation_contract', ['AllocationRecord::validate; complete public allocated resource plan'], lambda: allocation_contract(w, rows)),
            ('contract_success', ['source contract success_rules; native Link/WG plan/WAN/nonzero addition/journal/capacity'], lambda: contract_success(w, rows)),
            ('canonical_histories', ['stdout:13 all retained preparation histories and canonical publication chains'], lambda: canonical_histories(w, rows)),
            ('observation_bindings', ['BINDING_REGISTRY: every observation to its canonical history; explicit canonical roots',
                                      'attachment/provision.rs:878-885; attachment/movement.rs:824-835'], lambda: bind_observations(w, rows)),
            ('recorded_emitters', ['stdout:13 retained constructor/result receipts and resource identities'], lambda: recorded_emitters(w, rows)),
            ('writer_histories', ['stdout:13 every retained original writer, exact phase/window/status schedule'], lambda: writer_histories(w)),
            ('charge_conservation', ['stdout:13 charges_before_drop/charges_after_drop/handoff.charges_*'], lambda: charge_conservation(w)),
            ('handoff', ['stdout:13 handoff.complete/job counts/reservation/resources/preparation'], lambda: handoff(w)),
            ('no_authority', ['stdout:13 recursive *_authorized/multi_exit_runtime_proven/requirement8_complete', 'raw component scope; stdout:5-7'], lambda: no_authority(w, record, rows)),
            ('owner_identity', ['record.guest_boot_id; stdout:5,9,11,13 canonical owner epochs'], lambda: owner_identity(w, record, rows)),
            ('monotonic_deadlines', ['stdout:13 recursive births/requests/results/writers/scope_process_verified_at'], lambda: monotonic_deadlines(w)),
            ('bootstrap_scopes', ['stdout:13 operations/queries/preparation.bootstrap/bootstrap_queries/netfilter/writers'], lambda: bootstrap_scopes(w, rows)),
            ('controller_consistency', ['stdout:1-5,8-10,12-14 controller/gateway/original native identity/down host link'], lambda: controller_consistency(w, record, rows)),
            ('baseline_consistency', ['stdout:6-8,13 host_addition.admission; frozen authored baseline'], lambda: baseline_consistency(w, record, rows)),
        ]:
            check(name, refs, fn)
    if all(row['status'] == 'PASS' for row in receipt['checks']):
        receipt['verdict'] = receipt['full_bootstrap_witness_validation'] = 'PASS'
    return receipt


def save_receipt(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('receipt', type=Path, nargs='?')
    args = parser.parse_args()
    receipt = validate(args.record)
    data = (json.dumps(receipt, indent=2, allow_nan=False) + '\n').encode()
    if args.receipt is not None:
        try:
            save_receipt(args.receipt, data)
        except OSError as error:
            print('receipt_create_failed: ' + str(error), file=sys.stderr)
            return 1
    print(data.decode(), end='')
    return 0 if receipt['verdict'] == 'PASS' else 1


# Build after every referenced check function exists; reject unmapped guards
# before either CLI validation or receipt creation. No subprocess is executed.
GUARD_DISPOSITIONS = guard_dispositions()
GUARD_COUNTS = dict(extracted=len(GUARD_DISPOSITIONS),
                    enforced=sum(d['status']=='enforced' for d in GUARD_DISPOSITIONS.values()),
                    unenforceable_offline=sum(d['status']=='unenforceable_offline' for d in GUARD_DISPOSITIONS.values()))

if __name__ == '__main__':
    sys.exit(main())

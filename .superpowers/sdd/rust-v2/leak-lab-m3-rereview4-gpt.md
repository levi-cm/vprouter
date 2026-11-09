# Leak-lab M3 focused adversarial re-review, round 4

Target: rust/v2, `06baf40da6b847d04ddfd1593f978eb612e96040`. Initial checkout clean.

Scope: requested round-3 regressions, exact prefix reads and host-sampled window evaluation only. Offline Python stdlib tests; no live/network qualification. Written incrementally.

Status: COMPLETE. **FAIL — one new Important finding, R4-I1.** All requested round-3 regression variants are fixed. See the finding section and embedded deadline reproducer for the remaining false PASS.

## Required suites (once each)

- `cd tools/leak-lab && python3 -B -W error -m unittest test_leak_lab`: **341 tests, OK**, 14.124 s.
- `cd tools/leak-lab && python3 -B -W error -m unittest vm.test_vm`: **291 tests, OK**, 29.592 s.

Both used `TMPDIR=/var/tmp/leaklab-m3r4-gpt`. These are offline component tests.

`R3_partial_failed_fault_boundary_no_hold_probes`

```json
{
  "end_sequence": 6,
  "errors": [
    "probe_fault_sample_untrusted",
    "probe_log_unreadable",
    "probe_fault_sequence_missing"
  ],
  "exit": 2,
  "fault_sequence": null,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 0,
  "post_markers": 0,
  "probe": "INVALID",
  "reasons": [
    "probe_fault_sequence_missing",
    "probe_clock_stalled",
    "probe_post_fault_exit_missing",
    "probe_post_fault_marker_missing",
    "probe_hold_samples_invalid",
    "probe_hold_window_empty",
    "probe_hold_short"
  ],
  "result": "INVALID",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 5,
      "sequence": 6,
      "sha256": "54a83d039689f3a2acd6b8675ecd2817b5f777c22f66e24f79fcaa1ea1a5991f",
      "size": 531,
      "stat_end": 10.0,
      "stat_start": 10.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 5,
      "sequence": 6,
      "sha256": "54a83d039689f3a2acd6b8675ecd2817b5f777c22f66e24f79fcaa1ea1a5991f",
      "size": 531,
      "stat_end": 20.0,
      "stat_start": 20.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 5,
      "sequence": 6,
      "sha256": "54a83d039689f3a2acd6b8675ecd2817b5f777c22f66e24f79fcaa1ea1a5991f",
      "size": 531,
      "stat_end": 30.0,
      "stat_start": 30.0
    }
  ],
  "stop_proven": null,
  "trusted": true
}
```

`R3_partial_success_fault_boundary_no_hold_probes`

```json
{
  "end_sequence": 6,
  "errors": [
    "probe_fault_sample_untrusted",
    "probe_log_truncated",
    "probe_fault_sequence_missing"
  ],
  "exit": 2,
  "fault_sequence": null,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 0,
  "post_markers": 0,
  "probe": "INVALID",
  "reasons": [
    "probe_fault_sequence_missing",
    "probe_clock_stalled",
    "probe_post_fault_exit_missing",
    "probe_post_fault_marker_missing",
    "probe_hold_samples_invalid",
    "probe_hold_window_empty",
    "probe_hold_short"
  ],
  "result": "INVALID",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 5,
      "sequence": 6,
      "sha256": "c450c64ffca6af2f2a004112498328667e0aeb00750d07bebf244e213aa611db",
      "size": 531,
      "stat_end": 10.0,
      "stat_start": 10.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 5,
      "sequence": 6,
      "sha256": "c450c64ffca6af2f2a004112498328667e0aeb00750d07bebf244e213aa611db",
      "size": 531,
      "stat_end": 20.0,
      "stat_start": 20.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 5,
      "sequence": 6,
      "sha256": "c450c64ffca6af2f2a004112498328667e0aeb00750d07bebf244e213aa611db",
      "size": 531,
      "stat_end": 30.0,
      "stat_start": 30.0
    }
  ],
  "stop_proven": null,
  "trusted": true
}
```

`R3_early_burst_then_29s_silent`

```json
{
  "end_sequence": 6,
  "errors": [
    "probe_clock_stalled"
  ],
  "exit": 2,
  "fault_sequence": 2,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 2,
  "post_markers": 2,
  "probe": "INVALID",
  "reasons": [
    "probe_clock_stalled",
    "probe_hold_window_empty"
  ],
  "result": "INVALID",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "sequence": 2,
      "sha256": "e47b7902a814753cab71e744d8f30ec6b0cbe49cded36a20d7b9ddf07a1bf8a2",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 5,
      "sequence": 6,
      "sha256": "9ea9ef5216060e72d4d1c50519f2dc6bd89f55787372ac9237edd76a52d9e9cc",
      "size": 531,
      "stat_end": 10.0,
      "stat_start": 10.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 5,
      "sequence": 6,
      "sha256": "9ea9ef5216060e72d4d1c50519f2dc6bd89f55787372ac9237edd76a52d9e9cc",
      "size": 531,
      "stat_end": 20.0,
      "stat_start": 20.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 5,
      "sequence": 6,
      "sha256": "9ea9ef5216060e72d4d1c50519f2dc6bd89f55787372ac9237edd76a52d9e9cc",
      "size": 531,
      "stat_end": 30.0,
      "stat_start": 30.0
    }
  ],
  "stop_proven": null,
  "trusted": true
}
```

`R3_1Hz_early_burst_then_28s_silent`

```json
{
  "end_sequence": 6,
  "errors": [
    "probe_clock_stalled"
  ],
  "exit": 2,
  "fault_sequence": 2,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 2,
  "post_markers": 2,
  "probe": "INVALID",
  "reasons": [
    "probe_clock_stalled",
    "probe_hold_window_empty"
  ],
  "result": "INVALID",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "sequence": 2,
      "sha256": "9df794efe72fe53fc2e6ef8047da673507dd276cbcc8e084169e08197f309b08",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 5,
      "sequence": 6,
      "sha256": "1ae9c3cd44c7e688baab73f67f692d9ca4bd2e90bae047ca83db139213f6ee45",
      "size": 531,
      "stat_end": 10.0,
      "stat_start": 10.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 5,
      "sequence": 6,
      "sha256": "1ae9c3cd44c7e688baab73f67f692d9ca4bd2e90bae047ca83db139213f6ee45",
      "size": 531,
      "stat_end": 20.0,
      "stat_start": 20.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 5,
      "sequence": 6,
      "sha256": "1ae9c3cd44c7e688baab73f67f692d9ca4bd2e90bae047ca83db139213f6ee45",
      "size": 531,
      "stat_end": 30.0,
      "stat_start": 30.0
    }
  ],
  "stop_proven": null,
  "trusted": true
}
```

`R3_zero_hold_probes_two_pairs_during_end_status`

```json
{
  "end_sequence": 2,
  "errors": [
    "probe_clock_stalled"
  ],
  "exit": 2,
  "fault_sequence": 2,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 0,
  "post_markers": 0,
  "probe": "INVALID",
  "reasons": [
    "probe_clock_stalled",
    "probe_post_fault_exit_missing",
    "probe_post_fault_marker_missing",
    "probe_hold_window_empty"
  ],
  "result": "INVALID",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "sequence": 2,
      "sha256": "12ab140ec4ebf08ca8a70634debce38bd7872207546352d3cc30faa2eda7796f",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "sequence": 2,
      "sha256": "12ab140ec4ebf08ca8a70634debce38bd7872207546352d3cc30faa2eda7796f",
      "size": 177,
      "stat_end": 10.0,
      "stat_start": 10.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "sequence": 2,
      "sha256": "12ab140ec4ebf08ca8a70634debce38bd7872207546352d3cc30faa2eda7796f",
      "size": 177,
      "stat_end": 20.0,
      "stat_start": 20.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "sequence": 2,
      "sha256": "12ab140ec4ebf08ca8a70634debce38bd7872207546352d3cc30faa2eda7796f",
      "size": 177,
      "stat_end": 30.0,
      "stat_start": 30.0
    }
  ],
  "stop_proven": null,
  "trusted": true
}
```

`R3_1Hz_zero_hold_probes_two_pairs_during_end_status`

```json
{
  "end_sequence": 2,
  "errors": [
    "probe_clock_stalled"
  ],
  "exit": 2,
  "fault_sequence": 2,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 0,
  "post_markers": 0,
  "probe": "INVALID",
  "reasons": [
    "probe_clock_stalled",
    "probe_post_fault_exit_missing",
    "probe_post_fault_marker_missing",
    "probe_hold_window_empty"
  ],
  "result": "INVALID",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "sequence": 2,
      "sha256": "89e856136281a746bdd57ae6806dc3b7c2acc6f162a051e4028acba5d091c86f",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "sequence": 2,
      "sha256": "89e856136281a746bdd57ae6806dc3b7c2acc6f162a051e4028acba5d091c86f",
      "size": 177,
      "stat_end": 10.0,
      "stat_start": 10.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "sequence": 2,
      "sha256": "89e856136281a746bdd57ae6806dc3b7c2acc6f162a051e4028acba5d091c86f",
      "size": 177,
      "stat_end": 20.0,
      "stat_start": 20.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "sequence": 2,
      "sha256": "89e856136281a746bdd57ae6806dc3b7c2acc6f162a051e4028acba5d091c86f",
      "size": 177,
      "stat_end": 30.0,
      "stat_start": 30.0
    }
  ],
  "stop_proven": null,
  "trusted": true
}
```

`R4_healthy_positive_control`

```json
{
  "end_sequence": 62,
  "errors": [],
  "exit": 0,
  "fault_sequence": 2,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 30,
  "post_markers": 30,
  "probe": "PASS",
  "reasons": [],
  "result": "PASS",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "sequence": 2,
      "sha256": "abd1b2829187043351103ca0ee9213b35349d404a8b30fb7043d3e958b0d3017",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 21,
      "sequence": 22,
      "sha256": "28ed2a9e49d58399dad648168ce1c7053db765aa139deb603fb5a6d5a9887e32",
      "size": 1960,
      "stat_end": 10.0,
      "stat_start": 10.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 41,
      "sequence": 42,
      "sha256": "2114dcd3547da30496bdd40523a9858c6dd789e6f0d2751af5a0e37a551e40fc",
      "size": 3750,
      "stat_end": 20.0,
      "stat_start": 20.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 61,
      "sequence": 62,
      "sha256": "36747854eccf8afc404c3332e9781ceb6fe779ab34d7c7422a99af7970b72d5a",
      "size": 5540,
      "stat_end": 30.0,
      "stat_start": 30.0
    }
  ],
  "stop_proven": null,
  "trusted": true
}
```

## Round-3 disposition

| Reproducer | Disposition | Actual result on 06baf40 |
|---|---|---|
| R3_partial_failed_fault_boundary_no_hold_probes | **fixed** | exit 2 INVALID; S_fault null; probe_fault_sample_untrusted + probe_log_unreadable |
| R3_partial_success_fault_boundary_no_hold_probes | **fixed** | exit 2 INVALID; S_fault null; probe_fault_sample_untrusted + probe_log_truncated |
| R3_early_burst_then_29s_silent | **fixed** | exit 2 INVALID; S_fault 2, S_end 6; probe_hold_window_empty |
| R3_1Hz_early_burst_then_28s_silent | **fixed** | exit 2 INVALID; S_fault 2, S_end 6; probe_hold_window_empty |
| R3_zero_hold_probes_two_pairs_during_end_status | **fixed** | exit 2 INVALID; S_fault = S_end = 2; zero credited post-fault exits/markers |
| R3_1Hz_zero_hold_probes_two_pairs_during_end_status | **fixed** | exit 2 INVALID; S_fault = S_end = 2; zero credited post-fault exits/markers |

Frozen-clock fixtures also report probe_clock_stalled. The host-window rejection is independently present. Healthy stop-router 30 s control: exit 0 PASS, errors [], 30 post-fault pairs, samples at 0/10/20/30 s.

Adaptation: old cat injection became the next bounded head transfer (stat and guest digest still cover the complete pre-fault backlog). End-status injection is now gated to host deadline, so the new intermediate status calls do not accidentally generate hold traffic. Both original 0.25 s-step and 1 Hz variants were run.

## New false-PASS hunt

Inspecting only the requested two-file diff plus surrounding helpers/harness needed to execute it. Focus: complete-line boundary timing, long/late stat calls, per-window coverage distribution, prefix identity and digest/length quality.

`R4_sample_matrix_control`

```json
{
  "invalid_reasons": [],
  "verdict": "PASS"
}
```

`R4_sample_matrix_missing`

```json
{
  "invalid_reasons": [
    "probe_hold_samples_missing"
  ],
  "verdict": "INVALID"
}
```

`R4_sample_matrix_hash`

```json
{
  "invalid_reasons": [
    "probe_hold_prefix_mismatch"
  ],
  "verdict": "INVALID"
}
```

`R4_sample_matrix_size_short_claim`

```json
{
  "invalid_reasons": [
    "probe_hold_prefix_mismatch"
  ],
  "verdict": "INVALID"
}
```

`R4_sample_matrix_sequence_inflated`

```json
{
  "invalid_reasons": [
    "probe_hold_samples_invalid"
  ],
  "verdict": "INVALID"
}
```

`R4_sample_matrix_exit_sequence_inflated`

```json
{
  "invalid_reasons": [
    "probe_hold_samples_invalid"
  ],
  "verdict": "INVALID"
}
```

`R4_sample_matrix_size_regression`

```json
{
  "invalid_reasons": [
    "probe_hold_samples_invalid",
    "probe_hold_window_empty"
  ],
  "verdict": "INVALID"
}
```

`R4_sample_matrix_time_regression`

```json
{
  "invalid_reasons": [
    "probe_hold_samples_invalid",
    "probe_hold_window_late"
  ],
  "verdict": "INVALID"
}
```

`R4_sample_matrix_slow_stat`

```json
{
  "invalid_reasons": [
    "probe_hold_window_late"
  ],
  "verdict": "INVALID"
}
```

`R4_sample_matrix_deadline_early`

```json
{
  "invalid_reasons": [
    "probe_hold_short"
  ],
  "verdict": "INVALID"
}
```

`R4_sample_matrix_deadline_late`

```json
{
  "invalid_reasons": [
    "probe_hold_deadline_late"
  ],
  "verdict": "INVALID"
}
```

`R4_sample_matrix_nan`

```json
{
  "invalid_reasons": [
    "probe_hold_samples_invalid"
  ],
  "verdict": "INVALID"
}
```

`R4_sample_matrix_infinity`

```json
{
  "invalid_reasons": [
    "probe_hold_samples_invalid"
  ],
  "verdict": "INVALID"
}
```

`R4_sample_matrix_bool`

```json
{
  "invalid_reasons": [
    "probe_hold_samples_invalid"
  ],
  "verdict": "INVALID"
}
```

`R4_deadline_stat_delay_3s_healthy`

```json
{
  "end_sequence": 68,
  "errors": [
    "probe_hold_deadline_late"
  ],
  "exit": 2,
  "fault_sequence": 2,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 33,
  "post_markers": 33,
  "probe": "INVALID",
  "reasons": [
    "probe_hold_deadline_late"
  ],
  "result": "INVALID",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "sequence": 2,
      "sha256": "4f4c5ed68fa801c84b68ca85867f069411cbc342e4db323795c003eb4eb920d8",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 21,
      "sequence": 22,
      "sha256": "ae3a6e2fed993ab83665c130cfd00da8c55d8466e1bf60880418ef0e49391efd",
      "size": 1960,
      "stat_end": 10.0,
      "stat_start": 10.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 41,
      "sequence": 42,
      "sha256": "76d8cc63264b77025c907012f941f0facdeb854a4ef8edfbcc02c154dfe2bf58",
      "size": 3750,
      "stat_end": 20.0,
      "stat_start": 20.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 67,
      "sequence": 68,
      "sha256": "2c6d8b7a3e8d1681e7512c851a88789eb9501eab449507fcf15b2b9bbcb9a9f7",
      "size": 6077,
      "stat_end": 33.0,
      "stat_start": 30.0
    }
  ],
  "stop_proven": null,
  "trusted": true
}
```

`R4_deadline_stat_delay_1s_tail_silent`

```json
{
  "end_sequence": 44,
  "errors": [],
  "exit": 0,
  "fault_sequence": 2,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 21,
  "post_markers": 21,
  "probe": "PASS",
  "reasons": [],
  "result": "PASS",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "sequence": 2,
      "sha256": "d815db6d4e5c3736c3157fccc40fc02ac9cbe7faaf201d9204adf322ec9bf87c",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 21,
      "sequence": 22,
      "sha256": "1ca632856962f0ddc931fe96c397b9ff8739069ac0f59430f8c0ac6005ecbd7d",
      "size": 1960,
      "stat_end": 10.0,
      "stat_start": 10.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 41,
      "sequence": 42,
      "sha256": "7ed3b14be6b98992c4ff5109ccbf9ce4756ca227bf43182530a4d0a517770025",
      "size": 3750,
      "stat_end": 20.0,
      "stat_start": 20.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 43,
      "sequence": 44,
      "sha256": "502da22ab4a1599bf170de7c9a33c38526d268126ad9201c50f82618b7e1f4a6",
      "size": 3929,
      "stat_end": 31.0,
      "stat_start": 30.0
    }
  ],
  "stop_proven": null,
  "trusted": true
}
```

### NEW candidate reproduced: deadline-stat latency credits traffic after the hold

`R4_deadline_stat_delay_1s_tail_silent` returned **exit 0 PASS, errors []**, despite zero exit/marker attempts in the final nominal hold window `(20,30]`. Traffic runs normally through +20 s, then stalls; the deadline stat QGA exec starts at +30 s, takes 1 s before executing stat, and the client emits a pair at +31 s. All byte reads, lengths, hashes, final stop/snapshot and real evaluators remain unmodified. The +31 s pair changes S_end from 42 to 44 and is credited to the last window. Sample timing is stat_start=30, stat_end=31; the evaluator accepts it because 31-20 <= 15 and 31 <= 30+2.

This is a new route through the stat call itself, before the end status call. The old end-status regressions remain fixed. Classification and tighter controls follow.

`R4_deadline_no_delay_no_late_pair`

```json
{
  "end_sequence": 42,
  "errors": [
    "probe_hold_window_empty"
  ],
  "exit": 2,
  "fault_sequence": 2,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 20,
  "post_markers": 20,
  "probe": "INVALID",
  "reasons": [
    "probe_hold_window_empty"
  ],
  "result": "INVALID",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "sequence": 2,
      "sha256": "b2f60aaa07387d74f9581ed9e2ea4877120b54f292773bde56bbe201428dcb2e",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 21,
      "sequence": 22,
      "sha256": "d4ce53848339768f83d1877aae6cc32fc08b991f43e9ff12b9d595f0480d9574",
      "size": 1960,
      "stat_end": 10.0,
      "stat_start": 10.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 41,
      "sequence": 42,
      "sha256": "8ba63c24ffdb7f27d7dcf9531d9a4a675fe026aa534541c19bf8da021a028ebb",
      "size": 3750,
      "stat_end": 20.0,
      "stat_start": 20.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 41,
      "sequence": 42,
      "sha256": "8ba63c24ffdb7f27d7dcf9531d9a4a675fe026aa534541c19bf8da021a028ebb",
      "size": 3750,
      "stat_end": 30.0,
      "stat_start": 30.0
    }
  ],
  "stop_proven": null,
  "trace": [
    {
      "event": "pair",
      "offset": 0.25
    },
    {
      "event": "pair",
      "offset": 1.25
    },
    {
      "event": "pair",
      "offset": 2.25
    },
    {
      "event": "pair",
      "offset": 3.25
    },
    {
      "event": "pair",
      "offset": 4.25
    },
    {
      "event": "pair",
      "offset": 5.25
    },
    {
      "event": "pair",
      "offset": 6.25
    },
    {
      "event": "pair",
      "offset": 7.25
    },
    {
      "event": "pair",
      "offset": 8.25
    },
    {
      "event": "pair",
      "offset": 9.25
    },
    {
      "event": "pair",
      "offset": 10.25
    },
    {
      "event": "pair",
      "offset": 11.25
    },
    {
      "event": "pair",
      "offset": 12.25
    },
    {
      "event": "pair",
      "offset": 13.25
    },
    {
      "event": "pair",
      "offset": 14.25
    },
    {
      "event": "pair",
      "offset": 15.25
    },
    {
      "event": "pair",
      "offset": 16.25
    },
    {
      "event": "pair",
      "offset": 17.25
    },
    {
      "event": "pair",
      "offset": 18.25
    },
    {
      "event": "pair",
      "offset": 19.25
    },
    {
      "event": "deadline_stat_begin",
      "offset": 30.0
    },
    {
      "event": "deadline_stat_exec",
      "offset": 30.0
    }
  ],
  "trusted": true
}
```

`R4_deadline_1s_delay_no_late_pair`

```json
{
  "end_sequence": 42,
  "errors": [
    "probe_hold_window_empty"
  ],
  "exit": 2,
  "fault_sequence": 2,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 20,
  "post_markers": 20,
  "probe": "INVALID",
  "reasons": [
    "probe_hold_window_empty"
  ],
  "result": "INVALID",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "sequence": 2,
      "sha256": "aab56f96057afa0a51c0ddc7c9918ff7dd3519559ef9bc698d786289cebd2c21",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 21,
      "sequence": 22,
      "sha256": "882e7103be55f1cf86ff34c3867366cf3b6dc2223498a3833b6c19fa622fab12",
      "size": 1960,
      "stat_end": 10.0,
      "stat_start": 10.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 41,
      "sequence": 42,
      "sha256": "8e7340d2c9e27a1c72aea29644a46f2ef90c219bc0a7df5e03db02d43540a9b7",
      "size": 3750,
      "stat_end": 20.0,
      "stat_start": 20.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 41,
      "sequence": 42,
      "sha256": "8e7340d2c9e27a1c72aea29644a46f2ef90c219bc0a7df5e03db02d43540a9b7",
      "size": 3750,
      "stat_end": 31.0,
      "stat_start": 30.0
    }
  ],
  "stop_proven": null,
  "trace": [
    {
      "event": "pair",
      "offset": 0.25
    },
    {
      "event": "pair",
      "offset": 1.25
    },
    {
      "event": "pair",
      "offset": 2.25
    },
    {
      "event": "pair",
      "offset": 3.25
    },
    {
      "event": "pair",
      "offset": 4.25
    },
    {
      "event": "pair",
      "offset": 5.25
    },
    {
      "event": "pair",
      "offset": 6.25
    },
    {
      "event": "pair",
      "offset": 7.25
    },
    {
      "event": "pair",
      "offset": 8.25
    },
    {
      "event": "pair",
      "offset": 9.25
    },
    {
      "event": "pair",
      "offset": 10.25
    },
    {
      "event": "pair",
      "offset": 11.25
    },
    {
      "event": "pair",
      "offset": 12.25
    },
    {
      "event": "pair",
      "offset": 13.25
    },
    {
      "event": "pair",
      "offset": 14.25
    },
    {
      "event": "pair",
      "offset": 15.25
    },
    {
      "event": "pair",
      "offset": 16.25
    },
    {
      "event": "pair",
      "offset": 17.25
    },
    {
      "event": "pair",
      "offset": 18.25
    },
    {
      "event": "pair",
      "offset": 19.25
    },
    {
      "event": "deadline_stat_begin",
      "offset": 30.0
    },
    {
      "event": "deadline_stat_exec",
      "offset": 31.0
    }
  ],
  "trusted": true
}
```

`R4_deadline_1s_delay_pair_only_at_31`

```json
{
  "end_sequence": 44,
  "errors": [],
  "exit": 0,
  "fault_sequence": 2,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 21,
  "post_markers": 21,
  "probe": "PASS",
  "reasons": [],
  "result": "PASS",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "sequence": 2,
      "sha256": "1552c0ec5c4f4b0ac2823b5271c69594137a5d300dea0862db18fb363a1b8798",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 21,
      "sequence": 22,
      "sha256": "44cf02bb41c073bec480b21791480d7c8314b571a3f0edf1a5ebcfd50b99f4d2",
      "size": 1960,
      "stat_end": 10.0,
      "stat_start": 10.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 41,
      "sequence": 42,
      "sha256": "2ae3bc3a1d5123a1c4de60f3f5c69b51d5613985a34cb812ba403341f0781b2e",
      "size": 3750,
      "stat_end": 20.0,
      "stat_start": 20.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 43,
      "sequence": 44,
      "sha256": "a3ac6a01ae7ca05912503e5d0e5ef1a5da5cc191fbc1e8bf0ba3b0df9c69514b",
      "size": 3929,
      "stat_end": 31.0,
      "stat_start": 30.0
    }
  ],
  "stop_proven": null,
  "trace": [
    {
      "event": "pair",
      "offset": 0.25
    },
    {
      "event": "pair",
      "offset": 1.25
    },
    {
      "event": "pair",
      "offset": 2.25
    },
    {
      "event": "pair",
      "offset": 3.25
    },
    {
      "event": "pair",
      "offset": 4.25
    },
    {
      "event": "pair",
      "offset": 5.25
    },
    {
      "event": "pair",
      "offset": 6.25
    },
    {
      "event": "pair",
      "offset": 7.25
    },
    {
      "event": "pair",
      "offset": 8.25
    },
    {
      "event": "pair",
      "offset": 9.25
    },
    {
      "event": "pair",
      "offset": 10.25
    },
    {
      "event": "pair",
      "offset": 11.25
    },
    {
      "event": "pair",
      "offset": 12.25
    },
    {
      "event": "pair",
      "offset": 13.25
    },
    {
      "event": "pair",
      "offset": 14.25
    },
    {
      "event": "pair",
      "offset": 15.25
    },
    {
      "event": "pair",
      "offset": 16.25
    },
    {
      "event": "pair",
      "offset": 17.25
    },
    {
      "event": "pair",
      "offset": 18.25
    },
    {
      "event": "pair",
      "offset": 19.25
    },
    {
      "event": "deadline_stat_begin",
      "offset": 30.0
    },
    {
      "event": "pair",
      "offset": 31.0
    },
    {
      "event": "deadline_stat_exec",
      "offset": 31.0
    }
  ],
  "trusted": true
}
```

`R4_deadline_2s_delay_pair_only_at_32`

```json
{
  "end_sequence": 44,
  "errors": [],
  "exit": 0,
  "fault_sequence": 2,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 21,
  "post_markers": 21,
  "probe": "PASS",
  "reasons": [],
  "result": "PASS",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "sequence": 2,
      "sha256": "43aa362846ed9c3f135733677e9eb6bcc77c14d235cf8c30e7e9dfbbb18fa342",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 21,
      "sequence": 22,
      "sha256": "5b496107620a3465aeb1e7181fe478c3f1255c9e6c4152873d30e38f54fa5f12",
      "size": 1960,
      "stat_end": 10.0,
      "stat_start": 10.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 41,
      "sequence": 42,
      "sha256": "5008ae427af351e710dbe67df4e3641ba09de7b64baa79d26d4410a4269c52df",
      "size": 3750,
      "stat_end": 20.0,
      "stat_start": 20.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 43,
      "sequence": 44,
      "sha256": "09ce749243a5fceafa2d6c832597e6bd8598779dcf065c3bf2f09d40361449fb",
      "size": 3929,
      "stat_end": 32.0,
      "stat_start": 30.0
    }
  ],
  "stop_proven": null,
  "trace": [
    {
      "event": "pair",
      "offset": 0.25
    },
    {
      "event": "pair",
      "offset": 1.25
    },
    {
      "event": "pair",
      "offset": 2.25
    },
    {
      "event": "pair",
      "offset": 3.25
    },
    {
      "event": "pair",
      "offset": 4.25
    },
    {
      "event": "pair",
      "offset": 5.25
    },
    {
      "event": "pair",
      "offset": 6.25
    },
    {
      "event": "pair",
      "offset": 7.25
    },
    {
      "event": "pair",
      "offset": 8.25
    },
    {
      "event": "pair",
      "offset": 9.25
    },
    {
      "event": "pair",
      "offset": 10.25
    },
    {
      "event": "pair",
      "offset": 11.25
    },
    {
      "event": "pair",
      "offset": 12.25
    },
    {
      "event": "pair",
      "offset": 13.25
    },
    {
      "event": "pair",
      "offset": 14.25
    },
    {
      "event": "pair",
      "offset": 15.25
    },
    {
      "event": "pair",
      "offset": 16.25
    },
    {
      "event": "pair",
      "offset": 17.25
    },
    {
      "event": "pair",
      "offset": 18.25
    },
    {
      "event": "pair",
      "offset": 19.25
    },
    {
      "event": "deadline_stat_begin",
      "offset": 30.0
    },
    {
      "event": "pair",
      "offset": 32.0
    },
    {
      "event": "deadline_stat_exec",
      "offset": 32.0
    }
  ],
  "trusted": true
}
```

`R4_deadline_3s_delay_pair_only_at_33`

```json
{
  "end_sequence": 44,
  "errors": [
    "probe_hold_deadline_late"
  ],
  "exit": 2,
  "fault_sequence": 2,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 21,
  "post_markers": 21,
  "probe": "INVALID",
  "reasons": [
    "probe_hold_deadline_late"
  ],
  "result": "INVALID",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "sequence": 2,
      "sha256": "7656b97db4b24f1f9f2811916f42118bc5904439b93d999b0be1917d8352ad03",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 21,
      "sequence": 22,
      "sha256": "f01dd4ee862b026c08f63ee119700d596ce80cbbff3526d5c605e7070dedc83a",
      "size": 1960,
      "stat_end": 10.0,
      "stat_start": 10.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 41,
      "sequence": 42,
      "sha256": "7559e2978f5c93ef54e33364a177080b52d1c51f99a76de4312e50163a015f6e",
      "size": 3750,
      "stat_end": 20.0,
      "stat_start": 20.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 43,
      "sequence": 44,
      "sha256": "c6a10f4e86f6ad05a177e362e5cca7ea793a9f8d5d43f2a878af1cf0c65335c4",
      "size": 3929,
      "stat_end": 33.0,
      "stat_start": 30.0
    }
  ],
  "stop_proven": null,
  "trace": [
    {
      "event": "pair",
      "offset": 0.25
    },
    {
      "event": "pair",
      "offset": 1.25
    },
    {
      "event": "pair",
      "offset": 2.25
    },
    {
      "event": "pair",
      "offset": 3.25
    },
    {
      "event": "pair",
      "offset": 4.25
    },
    {
      "event": "pair",
      "offset": 5.25
    },
    {
      "event": "pair",
      "offset": 6.25
    },
    {
      "event": "pair",
      "offset": 7.25
    },
    {
      "event": "pair",
      "offset": 8.25
    },
    {
      "event": "pair",
      "offset": 9.25
    },
    {
      "event": "pair",
      "offset": 10.25
    },
    {
      "event": "pair",
      "offset": 11.25
    },
    {
      "event": "pair",
      "offset": 12.25
    },
    {
      "event": "pair",
      "offset": 13.25
    },
    {
      "event": "pair",
      "offset": 14.25
    },
    {
      "event": "pair",
      "offset": 15.25
    },
    {
      "event": "pair",
      "offset": 16.25
    },
    {
      "event": "pair",
      "offset": 17.25
    },
    {
      "event": "pair",
      "offset": 18.25
    },
    {
      "event": "pair",
      "offset": 19.25
    },
    {
      "event": "deadline_stat_begin",
      "offset": 30.0
    },
    {
      "event": "pair",
      "offset": 33.0
    },
    {
      "event": "deadline_stat_exec",
      "offset": 33.0
    }
  ],
  "trusted": true
}
```

## Important R4-I1 — Deadline stat latency lets post-deadline traffic certify an empty final hold window

**Locations:** `tools/leak-lab/vm/run_phase.py:3396` brackets a remote stat, so its actual size observation can occur anywhere between stat_start and stat_end; `:4613` starts this operation at the deadline. `tools/leak-lab/clientprobe.py:350` credits every new exit in the resulting prefix; `:357` permits stat_end through deadline + 2 s. No check distinguishes an exit written before the deadline from one first written during that grace period.

**Reproducer:** embedded `deadline.py`, cases `R4_deadline_1s_delay_pair_only_at_31` and `R4_deadline_2s_delay_pair_only_at_32`. These run the real stop-router phase, real exact prefix primitive, real probe evaluator and real client scanner through the existing fake-QGA harness. The only changed guest behavior is ordinary advancing timestamps, a stalled loop in the final window, and a 1 s / 2 s delay before the deadline stat executes. No verdict, sample, hash or byte-count result is fabricated. Actual last ordinary pair is at +19.25 s; the only later pair is at +31 s / +32 s. There are **zero attempts in the nominal final window (20,30]**.

**Actual:** both **exit 0 PASS**, probe PASS, errors [], S_fault=2, S_end=44, exact trusted final snapshot; stat_start=30 and stat_end=31 / 32. The final sample credits exit s=43, first written after the 30 s hold. This does not demonstrate a real-IP leak or zero traffic across the entire hold. It demonstrates a false claim of traffic coverage over its final nominal window. Classification is Important because this defeats the new end-boundary exclusion, even with a normal guest clock; the earlier full-hold zero-traffic failures are fixed.

**Controls:**

| Condition | Actual |
|---|---|
| No delay, no late pair | INVALID, probe_hold_window_empty, S_end=42 |
| Same 1 s stat delay, no late pair | INVALID, probe_hold_window_empty, S_end=42 |
| Same 1 s stat delay, sole tail pair at +31 | PASS, errors [], S_end=44 |
| Same 2 s stat delay, sole tail pair at +32 | PASS, errors [], S_end=44 |
| Same 3 s stat delay, sole tail pair at +33 | INVALID, probe_hold_deadline_late |

The controls isolate post-deadline content as the reason an otherwise empty final window turns from INVALID into PASS. The ordinary guest timestamps advance with host time; this does not rely on frozen timestamps, a forged hash, truncation, or the accepted offline-router policy.

**Suggested fix:** separate allowance for transport latency from eligibility of newly observed content. Require the final window's exit progress to have been established by a trusted prefix whose size-read end is at or before the hold deadline; a later confirmation can establish that the deadline was reached, but must not supply the missing pre-deadline exit. Schedule that progress read before the deadline with a bounded margin, or introduce an independently bounded snapshot protocol. If the observation straddles the deadline and progress was not already proven, report INVALID. Retain late bytes for LEAK detection. Add both delayed-stat/no-late-pair and delayed-stat/late-only-pair regressions. Merely allowing 2 s for the size-read round trip cannot prove when the credited exit occurred.

## Other scoped adversarial results

The evaluator mutation matrix has a PASS positive control. Missing samples, wrong prefix digest, shortened claimed size, inflated sequence/exit_sequence, regressing prefix size or host start time, a >15 s size-read window, short hold, >2 s late deadline, NaN, infinity, and boolean sequence all return INVALID with the expected quality reason. A real-runner 3 s delayed stat with healthy traffic is also INVALID. No second Critical/Important finding is established in the exact prefix primitive. No Minor findings raised.

The evaluated contract uses discrete host windows; one exit in each window does not itself prove a maximum 15 s interval between individual exits. That is not raised as a separate finding here: the new documented rule is per-window progress, while the explicit 15 s row-gap check remains on the guest clock.

`R4_prefix_matrix_control`

```json
{
  "problem": null,
  "sequence": 2,
  "trusted": true
}
```

`R4_prefix_matrix_stat_failure`

```json
{
  "problem": "probe_log_missing",
  "sequence": null,
  "trusted": false
}
```

`R4_prefix_matrix_digest_failure`

```json
{
  "problem": "probe_log_unreadable",
  "sequence": null,
  "trusted": false
}
```

`R4_prefix_matrix_data_failure`

```json
{
  "problem": "probe_log_unreadable",
  "sequence": null,
  "trusted": false
}
```

`R4_prefix_matrix_short_data`

```json
{
  "problem": "probe_log_truncated",
  "sequence": null,
  "trusted": false
}
```

`R4_prefix_matrix_wrong_guest_digest`

```json
{
  "problem": "probe_log_hash_mismatch",
  "sequence": null,
  "trusted": false
}
```

`R4_prefix_matrix_same_length_changed_bytes`

```json
{
  "problem": "probe_log_hash_mismatch",
  "sequence": null,
  "trusted": false
}
```

`R4_prefix_append_before_digest`

```json
{
  "final_leak": true,
  "final_problem": null,
  "final_size": 249,
  "prefix_size": 163,
  "sequence": 2,
  "trusted": true
}
```

`R4_prefix_append_before_data`

```json
{
  "final_leak": true,
  "final_problem": null,
  "final_size": 249,
  "prefix_size": 163,
  "sequence": 2,
  "trusted": true
}
```

### Exact-prefix primitive checks

Direct primitive checks independently confirmed: failed stat/digest/data execs, a short transfer, a wrong guest digest, and same-length altered bytes are untrusted and establish no sample sequence. A positive control is trusted. Appending a real-IP leak line between stat and digest, or between digest and transfer, preserves the original trusted prefix (S=2, 163 bytes); the later exact final read includes all 249 bytes and detects LEAK. Thus normal concurrent appends do not contaminate the earlier prefix or hide the later leak in this model.

## Embedded reproducers

Run from the repository root at `06baf40`, using Python stdlib only. Create `/var/tmp/leaklab-m3r4-gpt`, save the blocks under the filenames shown, and run each with `TMPDIR=/var/tmp/leaklab-m3r4-gpt python3 -B -W error /var/tmp/leaklab-m3r4-gpt/<filename>`. Run `regressions.py`, `hunt.py`, `deadline.py`, and `prefix.py`; `common.py` supplies definitions. These append fresh results to this report. The authoritative R4-I1 controls are in `deadline.py`, which ties guest timestamps to elapsed host time; `hunt.py` contains the initial exploratory version. The fake harness intercepts process, guest, capture and network operations; it does not replace the production prefix primitive, evaluator, scanner or phase verdict.

### common.py

```python
import contextlib
import json
import pathlib
import sys
from unittest import mock
sys.path.insert(0, str(pathlib.Path.cwd() / 'tools/leak-lab'))
from vm import test_vm as tv
rp = tv.run_phase
import clientprobe as cp
REPORT = pathlib.Path('.superpowers/sdd/rust-v2/leak-lab-m3-rereview4-gpt.md')

def record(name, data):
    line = name + ': ' + json.dumps(data, sort_keys=True)
    print(line, flush=True)
    with REPORT.open('a') as f:
        f.write('\n`' + name + '`\n\n```json\n' + json.dumps(data, sort_keys=True, indent=2) + '\n```\n')

def phase(name, kwargs, phase='stop-router', patches=None, duration=30):
    case = tv.ClientRunPhaseTests('test_client_idle_passes_with_both_captures_and_the_probe_log')
    case.setUp()
    try:
        with contextlib.ExitStack() as stack:
            if patches:
                patches(stack)
            code, r, client, events, out, err, evidence = case._run(phase, duration=duration, client_kwargs=kwargs)
        c = r['client']
        data = (evidence / tv.guest.CLIENT_PROBE_FILE).read_bytes()
        result = dict(exit=code, result=r['result'], errors=r['errors'],
                      probe=c.get('probe', {}).get('verdict'),
                      reasons=c.get('probe', {}).get('invalid_reasons'),
                      fault_sequence=c.get('fault_sequence'), end_sequence=c.get('hold_sequence_end'),
                      post_exits=c.get('probe', {}).get('post_fault_exit_attempts'),
                      post_markers=c.get('probe', {}).get('post_fault_marker_attempts'),
                      stop_proven=c.get('traffic_stop_proven'), trusted=c.get('probe_snapshot_trusted'),
                      log_read=c.get('probe_log_read'), latch=c.get('probe_leak_observed'),
                      samples=c.get('hold_samples'), guest_leak=b'"m":false' in client.log, persisted_leak=b'"m":false' in data)
        result["trace"] = getattr(client, "r4_trace", None)
        record(name, result)
        return result
    finally:
        case.doCleanups()

```

### regressions.py

```python
from pathlib import Path
exec(Path('/var/tmp/leaklab-m3r4-gpt/common.py').read_text())

def partial(stack, exitcode):
    original_wait=rp.wait_client_probe_control
    original_sample=rp.take_client_probe_sample
    def wait(client, run_id, **kw):
        flags=original_wait(client,run_id,**kw)
        client.probe_pair(); client.probe_pair()
        return flags
    def sample(client, run_id, *, base):
        if base is None:
            client.truncate_next_read=(2,exitcode)
        return original_sample(client,run_id,base=base)
    stack.enter_context(mock.patch.object(rp,'wait_client_probe_control',side_effect=wait))
    stack.enter_context(mock.patch.object(rp,'take_client_probe_sample',side_effect=sample))

for status,label in [(1,'failed'),(0,'success')]:
    phase('R3_partial_'+label+'_fault_boundary_no_hold_probes',dict(silent_hold=True,frozen_clock=True),patches=lambda s,status=status:partial(s,status))

def burst(stack, hz):
    original=rp.start_client_traffic
    def start(client,**kw):
        original(client,**kw)
        calls=[0]
        def maybe(now):
            calls[0]+=1
            if calls[0] in ((4,8) if hz else (1,2)):
                client.probe_pair()
        client.maybe_probe=maybe
    stack.enter_context(mock.patch.object(rp,'start_client_traffic',side_effect=start))
for hz,label in [(False,'R3_early_burst_then_29s_silent'),(True,'R3_1Hz_early_burst_then_28s_silent')]:
    phase(label,dict(frozen_clock=True),patches=lambda s,hz=hz:burst(s,hz))

def end_status(stack,hz):
    original_start=rp.start_client_traffic
    original_fault=rp.run_router_fault
    original_status=rp.read_client_status
    holder={}
    def start(client,**kw):
        holder['client']=client
        return original_start(client,**kw)
    def fault(*args,**kw):
        result=original_fault(*args,**kw)
        holder['end']=rp.time.monotonic()+30
        return result
    def status(client):
        if client.traffic_active and rp.time.monotonic()>=holder.get('end',float('inf')):
            for _ in range(2):
                if hz: rp.time.sleep(1)
                client.probe_pair()
        return original_status(client)
    for name,fn in [('start_client_traffic',start),('run_router_fault',fault),('read_client_status',status)]:
        stack.enter_context(mock.patch.object(rp,name,side_effect=fn))
for hz,label in [(False,'R3_zero_hold_probes_two_pairs_during_end_status'),(True,'R3_1Hz_zero_hold_probes_two_pairs_during_end_status')]:
    phase(label,dict(silent_hold=True,frozen_clock=True),patches=lambda s,hz=hz:end_status(s,hz))
phase('R4_healthy_positive_control',{})
```

### hunt.py

```python
from pathlib import Path
exec(Path('/var/tmp/leaklab-m3r4-gpt/common.py').read_text())
import hashlib
from test_leak_lab import client_hold_samples, ClientProbeTests

# Each trusted prefix must be a byte-for-byte prefix of the final evidence;
# execute negative mutations independently against a passing evaluator control.
case=ClientProbeTests()
data=case.frozen_log(3,step=10)
samples=client_hold_samples(data,[2,4,6,8],[(0,0),(10,10),(20,20),(30,30)])
base=case.frozen_values(end_sequence=8)
import copy
mutations={
 'control':lambda s:None,
 'missing':lambda s:s.clear(),
 'hash':lambda s:s[1].update(sha256='0'*64),
 'size_short_claim':lambda s:s[1].update(size=s[1]['size']-1),
 'sequence_inflated':lambda s:s[1].update(sequence=100),
 'exit_sequence_inflated':lambda s:s[1].update(exit_sequence=100),
 'size_regression':lambda s:s.__setitem__(2,dict(s[0],stat_start=20,stat_end=20)),
 'time_regression':lambda s:s[2].update(stat_start=9,stat_end=9),
 'slow_stat':lambda s:s[1].update(stat_end=15.001),
 'deadline_early':lambda s:s[-1].update(stat_start=29.9,stat_end=29.9),
 'deadline_late':lambda s:s[-1].update(stat_start=32.001,stat_end=32.001),
 'nan':lambda s:s[1].update(stat_start=float('nan')),
 'infinity':lambda s:s[1].update(stat_end=float('inf')),
 'bool':lambda s:s[1].update(sequence=True),
}
for label,mutate in mutations.items():
    current=copy.deepcopy(samples);mutate(current)
    result=cp.evaluate_probe_log(data,hold_samples=current,**base)
    record('R4_sample_matrix_'+label,{k:result[k] for k in ('verdict','invalid_reasons')})

# Delay a real size read in the fake QGA client. Exercise both full-traffic
# latency and data first appended during the delayed deadline stat.
def delayed_stat(stack, seconds, silence_tail=False):
    original_start=rp.start_client_traffic
    original_fault=rp.run_router_fault
    holder={}
    def start(client,**kw):
        holder['client']=client
        result=original_start(client,**kw)
        original_execute=client.execute
        def execute(program,args=(),**kw):
            command=args[-1] if args else ''
            t=rp.time.monotonic()
            offset=t-holder.get('h0',float('inf'))
            if command.startswith('stat -c %s') and 29.999<=offset<30.001 and client.traffic_active:
                rp.time.sleep(seconds)
                if silence_tail:
                    client.clock+=10
                    client.probe_pair()
            return original_execute(program,args,**kw)
        client.execute=execute
        return result
    def fault(*args,**kw):
        result=original_fault(*args,**kw)
        client=holder['client']
        holder['h0']=rp.time.monotonic()
        if silence_tail:
            client.hold_started_at=holder['h0']
            client.hold_plan=lambda offset:offset<=20
        return result
    stack.enter_context(mock.patch.object(rp,'start_client_traffic',side_effect=start))
    stack.enter_context(mock.patch.object(rp,'run_router_fault',side_effect=fault))
phase('R4_deadline_stat_delay_3s_healthy',{},patches=lambda s:delayed_stat(s,3))
phase('R4_deadline_stat_delay_1s_tail_silent',{},patches=lambda s:delayed_stat(s,1,True))
```

### deadline.py

```python
from pathlib import Path
exec(Path('/var/tmp/leaklab-m3r4-gpt/common.py').read_text())

# QGA request latency, rather than modified verdict/read logic. Log rows use
# an ordinary advancing guest clock tied to the fake host clock.
def deadline_hook(stack, *, delay, late_pair, last_in_hold=20):
    original_start=rp.start_client_traffic
    original_fault=rp.run_router_fault
    holder={}
    def start(client,**kw):
        holder['client']=client
        result=original_start(client,**kw)
        client.r4_trace=[]
        execute=client.execute
        pair=client.probe_pair
        def probe_pair():
            if 'h0' in holder:
                offset=rp.time.monotonic()-holder['h0']
                client.clock=holder['guest_base']+int(offset)
                client.r4_trace.append({'event':'pair','offset':round(offset,3)})
            pair()
        client.probe_pair=probe_pair
        def wrapped_execute(program,args=(),**kw):
            command=args[-1] if args else ''
            if holder.get('fault_done') and command.startswith('stat -c %s') and 'h0' not in holder:
                holder['h0']=rp.time.monotonic()
                holder['guest_base']=client.clock
                client.hold_started_at=holder['h0']
                client.hold_plan=lambda offset: offset<=last_in_hold
            offset=rp.time.monotonic()-holder.get('h0',float('inf'))
            if command.startswith('stat -c %s') and 29.999<=offset<30.001 and client.traffic_active:
                client.r4_trace.append({'event':'deadline_stat_begin','offset':round(offset,3)})
                rp.time.sleep(delay)
                if late_pair:
                    client.probe_pair()
                client.r4_trace.append({'event':'deadline_stat_exec','offset':round(rp.time.monotonic()-holder['h0'],3)})
            if command.strip()=='date +%s' and 'h0' in holder:
                client.clock=holder['guest_base']+int(rp.time.monotonic()-holder['h0'])
                return tv.ExecResult(0,str(client.clock).encode()+b'\n',b'')
            return execute(program,args,**kw)
        client.execute=wrapped_execute
        return result
    def fault(*args,**kw):
        result=original_fault(*args,**kw)
        holder['fault_done']=True
        return result
    stack.enter_context(mock.patch.object(rp,'start_client_traffic',side_effect=start))
    stack.enter_context(mock.patch.object(rp,'run_router_fault',side_effect=fault))

cases=[
 ('R4_deadline_no_delay_no_late_pair',0,False),
 ('R4_deadline_1s_delay_no_late_pair',1,False),
 ('R4_deadline_1s_delay_pair_only_at_31',1,True),
 ('R4_deadline_2s_delay_pair_only_at_32',2,True),
 ('R4_deadline_3s_delay_pair_only_at_33',3,True),
]
for name,delay,late in cases:
    phase(name,{},patches=lambda s,d=delay,l=late:deadline_hook(s,delay=d,late_pair=l))
```

### prefix.py

```python
from pathlib import Path
exec(Path('/var/tmp/leaklab-m3r4-gpt/common.py').read_text())
case=tv.ClientProbeReadTests()
log=case.line(1)+case.line(2,kind='marker')
for name,kw in [
 ('control',{}),('stat_failure',dict(stat_exit=1)),
 ('digest_failure',dict(digest_exit=1)),('data_failure',dict(data_exit=1)),
 ('short_data',dict(deliver=case.line(1))),
 ('wrong_guest_digest',dict(digest_of=log[::-1])),
 ('same_length_changed_bytes',dict(deliver=log.replace(b'"t":100',b'"t":101'))),
]:
    guest=case.Guest(log,**kw)
    sample,read=rp.take_client_probe_sample(guest,case.RUN_ID,base=None)
    record('R4_prefix_matrix_'+name,dict(trusted=read.trusted,problem=read.problem,sequence=sample['sequence'] if sample else None))

for when in ('before_digest','before_data'):
    guest=case.Guest(log)
    original=guest.execute
    appended=[False]
    def execute(program,args=(),**kw):
        command=args[-1] if args else ''
        target=command.startswith('head -c ') and ((' | sha256sum' in command)==(when=='before_digest'))
        if target and not appended[0]:
            appended[0]=True
            guest.log+=case.line(3,m=False)
        return original(program,args,**kw)
    guest.execute=execute
    sample,read=rp.take_client_probe_sample(guest,case.RUN_ID,base=None)
    final,problem=rp.read_client_probe_log_exact(guest)
    record('R4_prefix_append_'+when,dict(trusted=read.trusted,sequence=sample['sequence'],prefix_size=read.size,final_size=len(final),final_problem=problem,final_leak=cp.probe_prefix_flags(final)['leak']))
```

## Final disposition

All six named/adapted round-3 regression variants are **fixed** on 06baf40. One **new Important** false PASS remains: **R4-I1**, a deadline stat that observes a late-only exit within the 2 s grace period certifies an otherwise empty final nominal hold window. No Critical or Minor finding raised. Required suites: **341 tests OK** and **291 tests OK**, each invoked once. Passing offline component tests are not live leak qualification.

Accepted login-URL stderr and same-ID/same-IP offline-router hold samples are not treated as findings. No subagents, privileged commands, live networking, forbidden state/credential paths, archives or keys were used. No source changes, staging, commits or pushes were made.

Final checks: all five embedded Python blocks parse. Scratch `/var/tmp/leaklab-m3r4-gpt` deleted after every command/reproducer completed. HEAD and source preservation were rechecked before handback. The report is ignored by Git and is the only repository file written.

FAIL

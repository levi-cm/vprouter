# Leak-lab M3 adversarial re-review, round 5

Target: `rust/v2`, `9427346c2e969a69300c348911b05b18f78dc716`. Initial worktree clean.

Scope: R4 deadline regressions and new coverage false PASS in clientprobe evaluator and run_phase scheduling only. Offline Python stdlib; no live or network qualification. Report written incrementally. No subagents.

Status: COMPLETE. **FAIL — R5-I1 (Important), R5-M1 (Minor).** R4-I1 fixed; required suites both pass. Findings and reproducers below.

## Required suites (once each)

- `cd tools/leak-lab && python3 -B -W error -m unittest test_leak_lab`: **344 tests, OK**, 14.987 s, exit 0.
- `cd tools/leak-lab && python3 -B -W error -m unittest vm.test_vm`: **302 tests, OK**, 32.002 s, exit 0.

Both used `TMPDIR=/var/tmp/leaklab-m3r5-gpt`. Offline component evidence only.

## R4 deadline regressions

Adaptation: S_end now starts at hold +27 rather than +30. Preserve the original completion/emission instants (+30, +31, +32, +33), delaying the size request from its new start until that instant. The 1s/2s names refer to lateness after the deadline, not the now-longer request latency. Real prefix reads, samples, evaluator and phase verdict remain unmodified.

`R4_deadline_no_delay_no_late_pair`

```json
{
  "end_sequence": 68,
  "errors": [
    "probe_hold_window_late"
  ],
  "exit": 2,
  "fault_sequence": 28,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 20,
  "post_markers": 20,
  "probe": "INVALID",
  "reasons": [
    "probe_hold_window_late"
  ],
  "result": "INVALID",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "kind": "pre",
      "sequence": 2,
      "sha256": "ec1e22ab5cb4cd68c95fe48e6d86edebc8b4fae9db3adff1d0881b600a487654",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 27,
      "kind": "fault",
      "sequence": 28,
      "sha256": "69f64ec8a29ddd90a7726702671f9d88b55a2c5eb69c0f202504179ced671f9d",
      "size": 2497,
      "stat_end": 13.0,
      "stat_start": 13.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 55,
      "kind": "hold",
      "sequence": 56,
      "sha256": "2112dbcd09d47ac04f54ab36f74057322f3c14a1b89c1ddb82e3b445fdbce4ca",
      "size": 5003,
      "stat_end": 26.5,
      "stat_start": 26.5
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 67,
      "kind": "end",
      "sequence": 68,
      "sha256": "9fca87e6df4dfc0430e35b0dba2d0bf1acba9e9175f77acfc35a137c0d9b78b5",
      "size": 6077,
      "stat_end": 43.0,
      "stat_start": 40.0
    }
  ],
  "stop_proven": true,
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
      "offset": 27.0
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
  "end_sequence": 68,
  "errors": [
    "probe_hold_deadline_late",
    "probe_hold_window_late"
  ],
  "exit": 2,
  "fault_sequence": 28,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 20,
  "post_markers": 20,
  "probe": "INVALID",
  "reasons": [
    "probe_hold_window_late",
    "probe_hold_deadline_late"
  ],
  "result": "INVALID",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "kind": "pre",
      "sequence": 2,
      "sha256": "e42b03110fc0cbbd63198228012638b49dffcab12238f70729c387d35b154e46",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 27,
      "kind": "fault",
      "sequence": 28,
      "sha256": "077f5c38fea499045a7616a7da94ee9bce4584e0659dcd73dec3983e30aa65ab",
      "size": 2497,
      "stat_end": 13.0,
      "stat_start": 13.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 55,
      "kind": "hold",
      "sequence": 56,
      "sha256": "3adb59c40f3ec3edd0b51784ecb0d91247ca0f74dbfbc1a29893549d3f902be2",
      "size": 5003,
      "stat_end": 26.5,
      "stat_start": 26.5
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 67,
      "kind": "end",
      "sequence": 68,
      "sha256": "fd0d11852bbb3bcbc9492030558d1b2b8383f9d62f6647c7f591764d999d39e8",
      "size": 6077,
      "stat_end": 44.0,
      "stat_start": 40.0
    }
  ],
  "stop_proven": true,
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
      "offset": 27.0
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
  "end_sequence": 70,
  "errors": [
    "probe_hold_deadline_late",
    "probe_hold_window_late"
  ],
  "exit": 2,
  "fault_sequence": 28,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 21,
  "post_markers": 21,
  "probe": "INVALID",
  "reasons": [
    "probe_hold_window_late",
    "probe_hold_deadline_late"
  ],
  "result": "INVALID",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "kind": "pre",
      "sequence": 2,
      "sha256": "a6aeb3aa3066b677f3027c9092e391c071980120f1dda193004293bcd736f429",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 27,
      "kind": "fault",
      "sequence": 28,
      "sha256": "9be4f1a80531eb872593468bcf5b87c3fa5e80f516a07535a31cd79d0c6c20d1",
      "size": 2497,
      "stat_end": 13.0,
      "stat_start": 13.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 55,
      "kind": "hold",
      "sequence": 56,
      "sha256": "b93c47106030c7e632f19acdec4815eab97f62c35e76de806781b52d46e8bfda",
      "size": 5003,
      "stat_end": 26.5,
      "stat_start": 26.5
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 69,
      "kind": "end",
      "sequence": 70,
      "sha256": "3c6e9ee88f4603764faec7075005708ee59a8b0dc81bdb0098c0a9fe91e28fbb",
      "size": 6256,
      "stat_end": 44.0,
      "stat_start": 40.0
    }
  ],
  "stop_proven": true,
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
      "offset": 27.0
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
  "end_sequence": 70,
  "errors": [
    "probe_hold_deadline_late",
    "probe_hold_window_late"
  ],
  "exit": 2,
  "fault_sequence": 28,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 21,
  "post_markers": 21,
  "probe": "INVALID",
  "reasons": [
    "probe_hold_window_late",
    "probe_hold_deadline_late"
  ],
  "result": "INVALID",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "kind": "pre",
      "sequence": 2,
      "sha256": "a4d7ff11f63bf9c796d4dd44d9bc7177dd28e2e45e8e3ed72f77727641a8dbcd",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 27,
      "kind": "fault",
      "sequence": 28,
      "sha256": "ab314305ca4baaa5289b86cc46cf40cd234edfe7154900091079127ad12baa1d",
      "size": 2497,
      "stat_end": 13.0,
      "stat_start": 13.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 55,
      "kind": "hold",
      "sequence": 56,
      "sha256": "dacb75fc027ecf8698e986d2ec0956fdfec03301aed6740cb5e6ae3b87abf3b9",
      "size": 5003,
      "stat_end": 26.5,
      "stat_start": 26.5
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 69,
      "kind": "end",
      "sequence": 70,
      "sha256": "96c0f3ea908c99bbc2b86d293b4e7e3be6c05d15ca08506650f2e72f05ef3866",
      "size": 6256,
      "stat_end": 45.0,
      "stat_start": 40.0
    }
  ],
  "stop_proven": true,
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
      "offset": 27.0
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
  "end_sequence": 70,
  "errors": [
    "probe_hold_deadline_late",
    "probe_hold_window_late"
  ],
  "exit": 2,
  "fault_sequence": 28,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 21,
  "post_markers": 21,
  "probe": "INVALID",
  "reasons": [
    "probe_hold_window_late",
    "probe_hold_deadline_late"
  ],
  "result": "INVALID",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "kind": "pre",
      "sequence": 2,
      "sha256": "31a5e9775094cdd9048f3e9d0e63ff5fcc223e6abe84c171ee064b33e4e70e0c",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 27,
      "kind": "fault",
      "sequence": 28,
      "sha256": "a8338cc5d1c1205d8d77b1f094f8cf6f45eac8d4057d6e66be7606ade5ac3443",
      "size": 2497,
      "stat_end": 13.0,
      "stat_start": 13.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 55,
      "kind": "hold",
      "sequence": 56,
      "sha256": "906ef5e9b74a3ef592c0701b00f58f16276666c51f9287e23f30216ad8a2eff1",
      "size": 5003,
      "stat_end": 26.5,
      "stat_start": 26.5
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 69,
      "kind": "end",
      "sequence": 70,
      "sha256": "2c877d9a2f55adfb573a97768a8ab1445fc58432c279b80ef406c11b421c34ac",
      "size": 6256,
      "stat_end": 46.0,
      "stat_start": 40.0
    }
  ],
  "stop_proven": true,
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
      "offset": 27.0
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

`R5_silent_action_10s_resumes_after_return`

```json
{
  "end_sequence": 62,
  "errors": [],
  "exit": 0,
  "fault_sequence": 8,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 27,
  "post_markers": 27,
  "probe": "PASS",
  "reasons": [],
  "result": "PASS",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "kind": "pre",
      "sequence": 2,
      "sha256": "a9d02ca792ffe40e64d9bf9712ca3deba042beafc932cbb45ba9fa0d1000d70e",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 7,
      "kind": "fault",
      "sequence": 8,
      "sha256": "2b5b5d983c76177d4757c2483f76dbeb5a8b6acde03602540972f3bb156ac60d",
      "size": 708,
      "stat_end": 13.0,
      "stat_start": 13.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 33,
      "kind": "hold",
      "sequence": 34,
      "sha256": "4c255548bc80205b3ce3b180ba3d2a6880bb4ce1fa7192a1f41f7fc4bde750c2",
      "size": 3034,
      "stat_end": 26.5,
      "stat_start": 26.5
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 61,
      "kind": "end",
      "sequence": 62,
      "sha256": "b5a064d3214aff9edfdce7af6856d49dbf19989c14b928adca001999ca9eb8e4",
      "size": 5540,
      "stat_end": 40.0,
      "stat_start": 40.0
    }
  ],
  "stop_proven": true,
  "trace": [
    {
      "event": "action_begin",
      "offset": 0.0
    },
    {
      "event": "action_end",
      "offset": 10.0
    },
    {
      "event": "pair",
      "offset": 11.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 12.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 13.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 14.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 15.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 16.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 17.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 18.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 19.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 20.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 21.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 22.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 23.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 24.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 25.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 26.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 27.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 28.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 29.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 30.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 31.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 32.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 33.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 34.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 35.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 36.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 37.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 38.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 39.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 40.0,
      "stage": "after"
    }
  ],
  "trusted": true
}
```

`R5_healthy_action_10s_control`

```json
{
  "end_sequence": 82,
  "errors": [],
  "exit": 0,
  "fault_sequence": 28,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 27,
  "post_markers": 27,
  "probe": "PASS",
  "reasons": [],
  "result": "PASS",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "kind": "pre",
      "sequence": 2,
      "sha256": "a4e3ec0d9102b0f01455fe640bc8bb27f487b3a70835cc4749c88a06130263c3",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 27,
      "kind": "fault",
      "sequence": 28,
      "sha256": "dc6cb3e57f3db50ac3ca5e3ff1e192bf81efdc8193927c957058d207e8268414",
      "size": 2497,
      "stat_end": 13.0,
      "stat_start": 13.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 53,
      "kind": "hold",
      "sequence": 54,
      "sha256": "02b129e10195ab7c31d37f3e69a2fc4a7024601e73da9b1167de7b1b3a294211",
      "size": 4824,
      "stat_end": 26.5,
      "stat_start": 26.5
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 81,
      "kind": "end",
      "sequence": 82,
      "sha256": "164769acf5b28a50218d3ccb74809e1f7cc08612488996cbee9670dfafada20a",
      "size": 7330,
      "stat_end": 40.0,
      "stat_start": 40.0
    }
  ],
  "stop_proven": true,
  "trace": [
    {
      "event": "action_begin",
      "offset": 0.0
    },
    {
      "event": "pair",
      "offset": 1.0,
      "stage": "action"
    },
    {
      "event": "pair",
      "offset": 2.0,
      "stage": "action"
    },
    {
      "event": "pair",
      "offset": 3.0,
      "stage": "action"
    },
    {
      "event": "pair",
      "offset": 4.0,
      "stage": "action"
    },
    {
      "event": "pair",
      "offset": 5.0,
      "stage": "action"
    },
    {
      "event": "pair",
      "offset": 6.0,
      "stage": "action"
    },
    {
      "event": "pair",
      "offset": 7.0,
      "stage": "action"
    },
    {
      "event": "pair",
      "offset": 8.0,
      "stage": "action"
    },
    {
      "event": "pair",
      "offset": 9.0,
      "stage": "action"
    },
    {
      "event": "pair",
      "offset": 10.0,
      "stage": "action"
    },
    {
      "event": "action_end",
      "offset": 10.0
    },
    {
      "event": "pair",
      "offset": 11.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 12.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 13.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 14.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 15.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 16.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 17.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 18.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 19.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 20.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 21.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 22.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 23.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 24.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 25.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 26.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 27.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 28.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 29.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 30.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 31.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 32.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 33.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 34.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 35.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 36.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 37.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 38.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 39.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 40.0,
      "stage": "after"
    }
  ],
  "trusted": true
}
```

`R5_silent_action_10s_no_resume_control`

```json
{
  "end_sequence": 2,
  "errors": [
    "probe_gap"
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
    "probe_gap",
    "probe_post_fault_exit_missing",
    "probe_post_fault_marker_missing",
    "probe_hold_window_empty"
  ],
  "result": "INVALID",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "kind": "pre",
      "sequence": 2,
      "sha256": "39b2e20e6da2eb5e9f72b033ff64b85c4d72e98e431ac6738b0e15b891c6fa9d",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "kind": "fault",
      "sequence": 2,
      "sha256": "39b2e20e6da2eb5e9f72b033ff64b85c4d72e98e431ac6738b0e15b891c6fa9d",
      "size": 177,
      "stat_end": 13.0,
      "stat_start": 13.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "kind": "hold",
      "sequence": 2,
      "sha256": "39b2e20e6da2eb5e9f72b033ff64b85c4d72e98e431ac6738b0e15b891c6fa9d",
      "size": 177,
      "stat_end": 26.5,
      "stat_start": 26.5
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "kind": "end",
      "sequence": 2,
      "sha256": "39b2e20e6da2eb5e9f72b033ff64b85c4d72e98e431ac6738b0e15b891c6fa9d",
      "size": 177,
      "stat_end": 40.0,
      "stat_start": 40.0
    }
  ],
  "stop_proven": true,
  "trace": [
    {
      "event": "action_begin",
      "offset": 0.0
    },
    {
      "event": "action_end",
      "offset": 10.0
    }
  ],
  "trusted": true
}
```

`R5_silent_action_12s_resumes_after_return`

```json
{
  "end_sequence": 58,
  "errors": [],
  "exit": 0,
  "fault_sequence": 4,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 27,
  "post_markers": 27,
  "probe": "PASS",
  "reasons": [],
  "result": "PASS",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "kind": "pre",
      "sequence": 2,
      "sha256": "812b476efd35cdf0aca282094d41d881155fbdf68607bea74c48213cc7e48f37",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 3,
      "kind": "fault",
      "sequence": 4,
      "sha256": "be35004a553b724ee26e9470c6b8382dad2bfa07fbe24b48c2774af7e65116c3",
      "size": 354,
      "stat_end": 13.0,
      "stat_start": 13.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 29,
      "kind": "hold",
      "sequence": 30,
      "sha256": "33ec46aa30726b501512ae2fce9c2374d5fff9f876220d2eb87f855c6d22ee41",
      "size": 2676,
      "stat_end": 26.5,
      "stat_start": 26.5
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 57,
      "kind": "end",
      "sequence": 58,
      "sha256": "0eff978398a9caf3722ec517b2d2811837ced6c2f1cc3ce3c4422099f1f12b0e",
      "size": 5182,
      "stat_end": 40.0,
      "stat_start": 40.0
    }
  ],
  "stop_proven": true,
  "trace": [
    {
      "event": "action_begin",
      "offset": 0.0
    },
    {
      "event": "action_end",
      "offset": 12.0
    },
    {
      "event": "pair",
      "offset": 13.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 14.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 15.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 16.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 17.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 18.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 19.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 20.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 21.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 22.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 23.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 24.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 25.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 26.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 27.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 28.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 29.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 30.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 31.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 32.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 33.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 34.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 35.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 36.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 37.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 38.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 39.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 40.0,
      "stage": "after"
    }
  ],
  "trusted": true
}
```

## Confirmed new finding: R5-I1 — Important — post-action traffic certifies a completely silent action

Locations: `tools/leak-lab/vm/run_phase.py:4883` (halt before the next action sample), `tools/leak-lab/vm/run_phase.py:4912` (wait after the action before S_fault), `tools/leak-lab/clientprobe.py:312` (zero action samples allowed), `tools/leak-lab/clientprobe.py:389` (only aggregate adjacent-prefix growth checked).

**Actual reproducer:** `action.py` below, case `R5_silent_action_10s_resumes_after_return`: real stop-router phase **exit 0 / PASS**, probe **PASS**, errors/reasons **[]**, with trusted exact final log and proven stop. S_pre = (t=0, sequence=2). The router action occupies host [0,10]; the client emits **zero exit or marker attempts throughout it**. The first action sample would be due at +13, but the sampler is halted at +10 with no results. Traffic resumes only after action return: pairs at +11, +12, +13. The deliberately delayed S_fault at +13 sees sequence=8, and all three subsequent windows are accepted. No `action` sample exists. The +12 s silent-action variant likewise **exit 0 / PASS**: its only pre-S_fault pair is at +13, after action return.

Controls: healthy +10 s action **PASS**; silent +10 s action without resumed traffic **INVALID** (exit 2, `probe_gap`, also `probe_hold_window_empty`). All cases use the real prefix sampler, real action thread, real evaluator and combined phase verdict; only fake guest traffic/QGA timing and guest-clock readings are controlled. This is not thread starvation: the action ends strictly before the first scheduled action sample.

**Why this is a false coverage PASS:** the <=15 s prefix window spans both the entire action and an added post-action wait. It proves some traffic in that combined interval, not traffic during the router action. A completely silent critical transition is certified solely by traffic after it. This is separate from the documented two-window spacing bound and R4's deadline issue; all windows here are <=13.5 s, all deadlines are met, and guest time advances normally.

**Suggested fix:** preserve host-monotonic action start/end boundaries and an action-end prefix boundary without adding a wait to fill a probe loop. Require evidence of a new exit attempt observed within the action interval, separately from cadence/hold coverage, and reject an unobserved short action as INVALID. Where the action is too short to prove this using prefix samples, synchronize a client attempt with the action or explicitly mark action coverage unavailable; later traffic must not fill that gap. The evaluator must consume/check these action boundary observations rather than accepting `pre, fault` with arbitrary post-action growth. Preserve normal post-fault hold checks and leak parsing.

`R5_native_no_delay_tail_silent_control`

```json
{
  "end_sequence": 68,
  "errors": [],
  "exit": 0,
  "fault_sequence": 28,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 20,
  "post_markers": 20,
  "probe": "PASS",
  "reasons": [],
  "result": "PASS",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "kind": "pre",
      "sequence": 2,
      "sha256": "b10c7b4b0872ce018f28e773cc9676250933ee31187897443fc71e7dbd5a14f4",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 27,
      "kind": "fault",
      "sequence": 28,
      "sha256": "01213c4a63f421e61ca437b144a48923fb4e37dc2141a7e684bb6625777caf7e",
      "size": 2497,
      "stat_end": 13.0,
      "stat_start": 13.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 55,
      "kind": "hold",
      "sequence": 56,
      "sha256": "66c674059c4fa8ed423ff055245f086542e20899cd3a8a58075d62fa12bf4d87",
      "size": 5003,
      "stat_end": 26.5,
      "stat_start": 26.5
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 67,
      "kind": "end",
      "sequence": 68,
      "sha256": "5ec96becb0b2d822d9bfd47be2d3a9eb0608b08d134c96ef45bcf9ecf105b5be",
      "size": 6077,
      "stat_end": 40.0,
      "stat_start": 40.0
    }
  ],
  "stop_proven": true,
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
      "offset": 27.0
    },
    {
      "event": "deadline_stat_exec",
      "offset": 27.0
    }
  ],
  "trusted": true
}
```

`R5_native_no_delay_empty_final_window_control`

```json
{
  "end_sequence": 54,
  "errors": [
    "probe_hold_window_empty"
  ],
  "exit": 2,
  "fault_sequence": 28,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 13,
  "post_markers": 13,
  "probe": "INVALID",
  "reasons": [
    "probe_hold_window_empty"
  ],
  "result": "INVALID",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "kind": "pre",
      "sequence": 2,
      "sha256": "e810a5ca138e226b45e31afbafc07ec7781cffcecea8ad95064b6ae10e670ce1",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 27,
      "kind": "fault",
      "sequence": 28,
      "sha256": "011ca04e4cc3198e58b6af670301d9a73b811f3b6331b67de202e38039c63ad4",
      "size": 2497,
      "stat_end": 13.0,
      "stat_start": 13.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 53,
      "kind": "hold",
      "sequence": 54,
      "sha256": "bd3a127cbfaa490ec736594730bf9e44842314250a4b63ad7a2b2d1934572f6b",
      "size": 4824,
      "stat_end": 26.5,
      "stat_start": 26.5
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 53,
      "kind": "end",
      "sequence": 54,
      "sha256": "bd3a127cbfaa490ec736594730bf9e44842314250a4b63ad7a2b2d1934572f6b",
      "size": 4824,
      "stat_end": 40.0,
      "stat_start": 40.0
    }
  ],
  "stop_proven": true,
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
      "event": "deadline_stat_begin",
      "offset": 27.0
    },
    {
      "event": "deadline_stat_exec",
      "offset": 27.0
    }
  ],
  "trusted": true
}
```

`R5_in_deadline_1s_latency_pair_at_28_control`

```json
{
  "end_sequence": 56,
  "errors": [
    "probe_gap"
  ],
  "exit": 2,
  "fault_sequence": 28,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 14,
  "post_markers": 14,
  "probe": "INVALID",
  "reasons": [
    "probe_gap"
  ],
  "result": "INVALID",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "kind": "pre",
      "sequence": 2,
      "sha256": "cd7dbf91de1aac798409d8a1a3fad5d46e99a6e58915eda93fc279a9c4f822f7",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 27,
      "kind": "fault",
      "sequence": 28,
      "sha256": "73f3e56d1fe84b2e04729b45ca4eb26acfc7e31d0e88fe844625c4f6468897fa",
      "size": 2497,
      "stat_end": 13.0,
      "stat_start": 13.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 53,
      "kind": "hold",
      "sequence": 54,
      "sha256": "507de98dae2c085ddfff9836c126b4a0c2d2aa7e0dd51902ec3a797714140ca2",
      "size": 4824,
      "stat_end": 26.5,
      "stat_start": 26.5
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 55,
      "kind": "end",
      "sequence": 56,
      "sha256": "4e237b488657b7931973aa214a6015f394cf5a016474ad38bcc1fa746a81fb3d",
      "size": 5003,
      "stat_end": 41.0,
      "stat_start": 40.0
    }
  ],
  "stop_proven": true,
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
      "event": "deadline_stat_begin",
      "offset": 27.0
    },
    {
      "event": "pair",
      "offset": 28.0
    },
    {
      "event": "deadline_stat_exec",
      "offset": 28.0
    }
  ],
  "trusted": true
}
```

`R5_late_pair_at_31_empty_final_window_control`

```json
{
  "end_sequence": 56,
  "errors": [
    "probe_hold_deadline_late",
    "probe_gap"
  ],
  "exit": 2,
  "fault_sequence": 28,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 14,
  "post_markers": 14,
  "probe": "INVALID",
  "reasons": [
    "probe_gap",
    "probe_hold_window_late",
    "probe_hold_deadline_late"
  ],
  "result": "INVALID",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "kind": "pre",
      "sequence": 2,
      "sha256": "7ba7095ab379ff01731d3e20a195ab166e6bcd751e20f98173c9790bb93a609b",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 27,
      "kind": "fault",
      "sequence": 28,
      "sha256": "ae0974014af672e21b4b4d18745f51507ecf8c323efc34ca20eb676f00d19816",
      "size": 2497,
      "stat_end": 13.0,
      "stat_start": 13.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 53,
      "kind": "hold",
      "sequence": 54,
      "sha256": "7f989d53b257fe82ac25b473dc28bbb05ae62096d2251c02104065e9c6f9a700",
      "size": 4824,
      "stat_end": 26.5,
      "stat_start": 26.5
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 55,
      "kind": "end",
      "sequence": 56,
      "sha256": "4f42064ba5c32c571c8a423a0f0a4f20ccef8db4c1975213fa53342c3faa5195",
      "size": 5003,
      "stat_end": 44.0,
      "stat_start": 40.0
    }
  ],
  "stop_proven": true,
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
      "event": "deadline_stat_begin",
      "offset": 27.0
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

`R5_late_pair_at_32_empty_final_window_control`

```json
{
  "end_sequence": 56,
  "errors": [
    "probe_hold_deadline_late",
    "probe_gap"
  ],
  "exit": 2,
  "fault_sequence": 28,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 14,
  "post_markers": 14,
  "probe": "INVALID",
  "reasons": [
    "probe_gap",
    "probe_hold_window_late",
    "probe_hold_deadline_late"
  ],
  "result": "INVALID",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "kind": "pre",
      "sequence": 2,
      "sha256": "d4da1ae4d3c2657582982fb5560f6a96f22b893f7f996084752d2fc70da46f42",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 27,
      "kind": "fault",
      "sequence": 28,
      "sha256": "014c1e23ebfd1ac38f0bb5148ea203bd794ea0a69957371feb97e72b99cdcab8",
      "size": 2497,
      "stat_end": 13.0,
      "stat_start": 13.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 53,
      "kind": "hold",
      "sequence": 54,
      "sha256": "a3c9838e7bee6f278518e0548b203cd59b56576cdc6bfb8b255c8fdbe2157564",
      "size": 4824,
      "stat_end": 26.5,
      "stat_start": 26.5
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 55,
      "kind": "end",
      "sequence": 56,
      "sha256": "636bce0c79312738a12c876e88252e1474205a2d842d19fa06ad0208ebc1b8da",
      "size": 5003,
      "stat_end": 45.0,
      "stat_start": 40.0
    }
  ],
  "stop_proven": true,
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
      "event": "deadline_stat_begin",
      "offset": 27.0
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

`R5_healthy_native_schedule_control`

```json
{
  "end_sequence": 82,
  "errors": [],
  "exit": 0,
  "fault_sequence": 28,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 27,
  "post_markers": 27,
  "probe": "PASS",
  "reasons": [],
  "result": "PASS",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "kind": "pre",
      "sequence": 2,
      "sha256": "67b5512fa73291c520b011741f64b05705132ab319e2bbedaf20c6f38d68ef9d",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 27,
      "kind": "fault",
      "sequence": 28,
      "sha256": "57aaa8b2129ab7ddd76a7070a07ab552543fec58c09eb678f11a56c7a24564a5",
      "size": 2497,
      "stat_end": 13.0,
      "stat_start": 13.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 55,
      "kind": "hold",
      "sequence": 56,
      "sha256": "e0c9f0d98a2bf8435835975799b9aa56dc60405a4877789797901599fcf7f3c2",
      "size": 5003,
      "stat_end": 26.5,
      "stat_start": 26.5
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 81,
      "kind": "end",
      "sequence": 82,
      "sha256": "30f2f726a804408d94199ed6a39258c85d35481d5affa2b7bc599a76ddab5f1e",
      "size": 7330,
      "stat_end": 40.0,
      "stat_start": 40.0
    }
  ],
  "stop_proven": true,
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
      "event": "pair",
      "offset": 20.25
    },
    {
      "event": "pair",
      "offset": 21.25
    },
    {
      "event": "pair",
      "offset": 22.25
    },
    {
      "event": "pair",
      "offset": 23.25
    },
    {
      "event": "pair",
      "offset": 24.25
    },
    {
      "event": "pair",
      "offset": 25.25
    },
    {
      "event": "pair",
      "offset": 26.25
    },
    {
      "event": "deadline_stat_begin",
      "offset": 27.0
    },
    {
      "event": "deadline_stat_exec",
      "offset": 27.0
    }
  ],
  "trusted": true
}
```

`R5_window_exact_15_control`

```json
{
  "end_sequence": 82,
  "errors": [],
  "exit": 0,
  "fault_sequence": 28,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 27,
  "post_markers": 27,
  "probe": "PASS",
  "reasons": [],
  "result": "PASS",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "kind": "pre",
      "sequence": 2,
      "sha256": "b64d23979f79847a23770a8b7e8350f9032116fce8259dd76ad2135896b44205",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 27,
      "kind": "fault",
      "sequence": 28,
      "sha256": "6d1f471c2224146a43de486df54e4b3d2ccc2ee7d1b2237aa37031a8bcc07821",
      "size": 2497,
      "stat_end": 13.0,
      "stat_start": 13.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 57,
      "kind": "hold",
      "sequence": 58,
      "sha256": "c97ca728a3ba1633f85d77090c24d9ec58ca7ee6d6262941fdd1cf74898aec75",
      "size": 5182,
      "stat_end": 28.0,
      "stat_start": 26.5
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 81,
      "kind": "end",
      "sequence": 82,
      "sha256": "6e7a786cd91e06329f520e7ae3808c8f1d5a28e691e3c2db857289372ecc6871",
      "size": 7330,
      "stat_end": 40.0,
      "stat_start": 40.0
    }
  ],
  "stop_proven": true,
  "trace": [
    {
      "kind": "fault",
      "raw_window": 13.0,
      "recorded_end": 13.0,
      "recorded_start": 13.0
    },
    {
      "kind": "hold",
      "raw_window": 15.0,
      "recorded_end": 28.0,
      "recorded_start": 26.5
    },
    {
      "kind": "end",
      "raw_window": 13.5,
      "recorded_end": 40.0,
      "recorded_start": 40.0
    }
  ],
  "trusted": true
}
```

`R5_window_15_0004_rounding`

```json
{
  "end_sequence": 82,
  "errors": [],
  "exit": 0,
  "fault_sequence": 28,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 27,
  "post_markers": 27,
  "probe": "PASS",
  "reasons": [],
  "result": "PASS",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "kind": "pre",
      "sequence": 2,
      "sha256": "1139393444babb582f797875092ff5e8e85e3a0507f0cd35fd739b056df6e558",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 27,
      "kind": "fault",
      "sequence": 28,
      "sha256": "bde3277b164a2c74e10ed5785d9ab14303603e44d6b45f17a106093ecf8263ad",
      "size": 2497,
      "stat_end": 13.0,
      "stat_start": 13.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 57,
      "kind": "hold",
      "sequence": 58,
      "sha256": "72b30c6e57b1dfba9b697dfc16e1d20656ff252f6edd6a49ec1f52390e23382d",
      "size": 5182,
      "stat_end": 28.0,
      "stat_start": 26.5
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 81,
      "kind": "end",
      "sequence": 82,
      "sha256": "92c62b73abdaafaa6b434f6301e9b842d591e80a52d65c8a47f964c3e0cea8c9",
      "size": 7330,
      "stat_end": 40.0,
      "stat_start": 40.0
    }
  ],
  "stop_proven": true,
  "trace": [
    {
      "kind": "fault",
      "raw_window": 13.0,
      "recorded_end": 13.0,
      "recorded_start": 13.0
    },
    {
      "kind": "hold",
      "raw_window": 15.000400000018999,
      "recorded_end": 28.0,
      "recorded_start": 26.5
    },
    {
      "kind": "end",
      "raw_window": 13.5,
      "recorded_end": 40.0,
      "recorded_start": 40.0
    }
  ],
  "trusted": true
}
```

`R5_window_15_001_control`

```json
{
  "end_sequence": 82,
  "errors": [
    "probe_hold_window_late"
  ],
  "exit": 2,
  "fault_sequence": 28,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 27,
  "post_markers": 27,
  "probe": "INVALID",
  "reasons": [
    "probe_hold_window_late"
  ],
  "result": "INVALID",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "kind": "pre",
      "sequence": 2,
      "sha256": "db0e268286e7e7aadfc1810257df24b26ec1f0be73e18e6650689b5a30c305e8",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 27,
      "kind": "fault",
      "sequence": 28,
      "sha256": "66241545e8808b1b0326b4157dd0cf1ff6037fc34bd86be7b2ce4880da3f009d",
      "size": 2497,
      "stat_end": 13.0,
      "stat_start": 13.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 57,
      "kind": "hold",
      "sequence": 58,
      "sha256": "ba3bc20d15cbfece65eb044f620d5bfb78b31cc1c9acb766005be9bccb9035d2",
      "size": 5182,
      "stat_end": 28.001,
      "stat_start": 26.5
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 81,
      "kind": "end",
      "sequence": 82,
      "sha256": "3288e12033e343c58efb8eaa452453e2bf335b34b1cf5f550becfdd4f3841244",
      "size": 7330,
      "stat_end": 40.0,
      "stat_start": 40.0
    }
  ],
  "stop_proven": true,
  "trace": [
    {
      "kind": "fault",
      "raw_window": 13.0,
      "recorded_end": 13.0,
      "recorded_start": 13.0
    },
    {
      "kind": "hold",
      "raw_window": 15.001000000047497,
      "recorded_end": 28.001,
      "recorded_start": 26.5
    },
    {
      "kind": "end",
      "raw_window": 13.5,
      "recorded_end": 40.0,
      "recorded_start": 40.0
    }
  ],
  "trusted": true
}
```

`R5_window_16_control`

```json
{
  "end_sequence": 82,
  "errors": [
    "probe_hold_window_late"
  ],
  "exit": 2,
  "fault_sequence": 28,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 27,
  "post_markers": 27,
  "probe": "INVALID",
  "reasons": [
    "probe_hold_window_late"
  ],
  "result": "INVALID",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "kind": "pre",
      "sequence": 2,
      "sha256": "0cb671284f4407a064dec7accab238c1baa684086bb9dc3b3b120fd038c421cd",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 27,
      "kind": "fault",
      "sequence": 28,
      "sha256": "831f7382bcfa464af447d866a07d298f7f9e73b15bd483a60b3bc4de0d6dcb27",
      "size": 2497,
      "stat_end": 13.0,
      "stat_start": 13.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 59,
      "kind": "hold",
      "sequence": 60,
      "sha256": "5e1ab8fa91421b39f09e41d53e82b96138ebe1a6a8a82bbe52357b88ebd5c7bf",
      "size": 5361,
      "stat_end": 29.0,
      "stat_start": 26.5
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 81,
      "kind": "end",
      "sequence": 82,
      "sha256": "80bf3c5082f98c0fed25f88ffce77755912d3292fc0b194efea008a237a76cc6",
      "size": 7330,
      "stat_end": 40.0,
      "stat_start": 40.0
    }
  ],
  "stop_proven": true,
  "trace": [
    {
      "kind": "fault",
      "raw_window": 13.0,
      "recorded_end": 13.0,
      "recorded_start": 13.0
    },
    {
      "kind": "hold",
      "raw_window": 16.0,
      "recorded_end": 29.0,
      "recorded_start": 26.5
    },
    {
      "kind": "end",
      "raw_window": 13.5,
      "recorded_end": 40.0,
      "recorded_start": 40.0
    }
  ],
  "trusted": true
}
```

## Additional finding: R5-M1 — Minor — millisecond rounding admits a host window over 15 s

Locations: `tools/leak-lab/vm/run_phase.py:3617` (nearest-millisecond offsets), `tools/leak-lab/clientprobe.py:390` (bound evaluated only on those rounded offsets).

Reproducer: `windows.py`, `R5_window_15_0004_rounding`. A first-hold size request delayed by 1.5004 s produces an actual host window **15.000400000018999 s**, but serializes the endpoints as 13.000 and 28.000. The real phase and probe evaluator return **exit 0 / PASS**, errors **[]**. The runner does not check raw host window lengths. Positive control at exactly 15 s PASSes; controls at 15.001 s and 16 s return **exit 2 / INVALID**, `probe_hold_window_late`.

This violates the literal <=15 s criterion but is limited here to sub-millisecond precision loss; it is Minor rather than an unbounded observation gap. Suggested fix: check unrounded monotonic bounds in the runner and persist sufficient precision for independent evaluation, or round start downward and end upward before applying the maximum. Do not round a possible overrun into a passing interval.

## Deadline regression dispositions

- `R4_deadline_no_delay_no_late_pair`: **fixed / INVALID**, exit 2, `probe_hold_window_late`. This preserved-old-completion control now holds S_end's +27 request until +30, making the last host window 16.5 s. It contains traffic under the new split; the old (20,30] empty-window assertion no longer describes the new schedule.
- `R4_deadline_1s_delay_no_late_pair`: **fixed / INVALID**, exit 2, `probe_hold_deadline_late` and `probe_hold_window_late`.
- `R4_deadline_1s_delay_pair_only_at_31`: **fixed / INVALID**, exit 2, both late-deadline and late-window reasons. S_end starts at hold +27 and ends +31; the pair really is written at +31.
- `R4_deadline_2s_delay_pair_only_at_32`: **fixed / INVALID**, exit 2, both late-deadline and late-window reasons. S_end ends +32; pair written +32.
- `R4_deadline_3s_delay_pair_only_at_33`: **fixed / INVALID**, exit 2, both reasons; pair written +33.

Additional controls explicitly adapt the silent tail to the new final window (13.5,27]: no-delay/no-late-pair **INVALID**, `probe_hold_window_empty`; only late pairs at +31/+32 **INVALID**, `probe_hold_deadline_late` (also guest gap and window overrun). Healthy native schedule **PASS**. Native schedule with ordinary pairs only through +19.25 **PASS** because its final window contains pairs; this is expected under the revised split. The +28 pair / last ordinary pair +12.25 control is **INVALID** solely for `probe_gap` (guest gap is 16 s); neither deadline nor host-window check rejects it. These actual outputs are retained above without treating the latter as a successful positive control.

## Scope conclusion

One new Important action-coverage false PASS and one Minor precision false PASS were reproduced end to end. No Critical finding. The multi-second post-deadline false PASS R4-I1 is fixed. Exact prefix/hash and sequence comparison exclude already complete rows in S_pre from later adjacent-prefix credit; this review did not reproduce another such defect. The scheduling bounds otherwise reject the tested 15.001 s/16 s windows. These are offline local fake-QGA results, not live traffic or real leak qualification.

## Embedded reproducers

From repository root at the target commit, create `/var/tmp/leaklab-m3r5-gpt`, save the following blocks under their filenames, and run each script (except `common.py`) with `TMPDIR=/var/tmp/leaklab-m3r5-gpt python3 -B -W error /var/tmp/leaklab-m3r5-gpt/<filename>`. The scripts append actual results to this report. The existing harness replaces VM/process/network operations; prefix reading, coverage sampling, client evaluator and combined verdict execute normally. No source edits are required.

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
REPORT = pathlib.Path('.superpowers/sdd/rust-v2/leak-lab-m3-rereview5-gpt.md')

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

### deadline.py

```python
from pathlib import Path
exec(Path('/var/tmp/leaklab-m3r5-gpt/common.py').read_text())

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
            if command.startswith('stat -c %s') and 26.999<=offset<27.001 and client.traffic_active:
                client.r4_trace.append({'event':'deadline_stat_begin','offset':round(offset,3)})
                rp.time.sleep(max(0,30+delay-offset))
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

### deadline_controls.py

```python
from pathlib import Path
exec(Path('/var/tmp/leaklab-m3r5-gpt/common.py').read_text())

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
            if command.startswith('stat -c %s') and 26.999<=offset<27.001 and client.traffic_active:
                client.r4_trace.append({'event':'deadline_stat_begin','offset':round(offset,3)})
                rp.time.sleep(max(0,delay-offset))
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
 ('R5_native_no_delay_tail_silent_control',27,False,20),
 ('R5_native_no_delay_empty_final_window_control',27,False,13),
 ('R5_in_deadline_1s_latency_pair_at_28_control',28,True,13),
 ('R5_late_pair_at_31_empty_final_window_control',31,True,13),
 ('R5_late_pair_at_32_empty_final_window_control',32,True,13),
 ('R5_healthy_native_schedule_control',27,False,100),
]
for name,until,late,last in cases:
    phase(name,{},patches=lambda s,u=until,l=late,t=last:deadline_hook(s,delay=u,late_pair=l,last_in_hold=t))
```

### action.py

```python
from pathlib import Path
exec(Path('/var/tmp/leaklab-m3r5-gpt/common.py').read_text())

def action_hook(stack, duration, silent=True, resume=True):
    original_start=rp.start_client_traffic
    original_fault=rp.run_router_fault
    h={}
    def start(client, **kw):
        result=original_start(client, **kw)
        h.update(client=client,t0=rp.time.monotonic(),g0=client.clock,stage='before')
        client.r4_trace=[]
        pair=client.probe_pair
        execute=client.execute
        def now(): return rp.time.monotonic()-h['t0']
        def guest_now(): return h['g0']+int(now())
        def probe_pair():
            client.clock=guest_now()
            client.r4_trace.append(dict(event='pair',offset=round(now(),4),stage=h['stage']))
            pair()
        def wrapped(program,args=(),**kw):
            command=args[-1] if args else ''
            if command.strip()=='date +%s':
                client.clock=guest_now()
                return tv.ExecResult(0,f'{client.clock}\n'.encode(),b'')
            return execute(program,args,**kw)
        client.probe_pair=probe_pair
        client.execute=wrapped
        return result
    def fault(*args,**kw):
        c=h['client']
        h['stage']='action'
        c.r4_trace.append(dict(event='action_begin',offset=round(rp.time.monotonic()-h['t0'],4)))
        if silent:
            c.hold_started_at=rp.time.monotonic()-0.001
            c.hold_plan=lambda offset:False
        rp.time.sleep(duration)
        result=original_fault(*args,**kw)
        c.r4_trace.append(dict(event='action_end',offset=round(rp.time.monotonic()-h['t0'],4)))
        h['stage']='after'
        if resume: c.hold_plan=None
        return result
    stack.enter_context(mock.patch.object(rp,'start_client_traffic',side_effect=start))
    stack.enter_context(mock.patch.object(rp,'run_router_fault',side_effect=fault))

for name,duration,silent,resume in [
 ('R5_silent_action_10s_resumes_after_return',10,True,True),
 ('R5_healthy_action_10s_control',10,False,True),
 ('R5_silent_action_10s_no_resume_control',10,True,False),
 ('R5_silent_action_12s_resumes_after_return',12,True,True),
]:
    phase(name,{},patches=lambda s,d=duration,q=silent,r=resume:action_hook(s,d,q,r))
```

### windows.py

```python
from pathlib import Path
exec(Path('/var/tmp/leaklab-m3r5-gpt/common.py').read_text())

def window_hook(stack,delay):
    original=rp.take_client_coverage_sample
    previous=[]
    def take(client,run_id,**kw):
        execute=client.execute
        def wrapped(program,args=(),**opts):
            command=args[-1] if args else ''
            if command.startswith('stat -c %s'):
                rp.time.sleep(delay)
            return execute(program,args,**opts)
        if kw['kind']=='hold':client.execute=wrapped
        try: result=original(client,run_id,**kw)
        finally:client.execute=execute
        if not hasattr(client,'r4_trace'):client.r4_trace=[]
        if previous:
            client.r4_trace.append(dict(kind=kw['kind'],raw_window=result.read.stat_end-previous[-1],recorded_start=result.sample['stat_start'],recorded_end=result.sample['stat_end']))
        previous.append(result.read.stat_start)
        return result
    stack.enter_context(mock.patch.object(rp,'take_client_coverage_sample',side_effect=take))
for name,delay in [
 ('R5_window_exact_15_control',1.5),
 ('R5_window_15_0004_rounding',1.5004),
 ('R5_window_15_001_control',1.501),
 ('R5_window_16_control',2.5),
]:
    phase(name,{},patches=lambda s,d=delay:window_hook(s,d))
```

`R5_fault_applied_at_start_silent_10s`

```json
{
  "end_sequence": 62,
  "errors": [],
  "exit": 0,
  "fault_sequence": 8,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 27,
  "post_markers": 27,
  "probe": "PASS",
  "reasons": [],
  "result": "PASS",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "kind": "pre",
      "sequence": 2,
      "sha256": "13fd37e203b22734eb5402e26e86ba16f80a15d502c0e0eda02ae5ce817a13ca",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 7,
      "kind": "fault",
      "sequence": 8,
      "sha256": "6f121942243d433beab36ce42cf41c4a1b6e512b185451205a766fb51afeabc5",
      "size": 708,
      "stat_end": 13.0,
      "stat_start": 13.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 33,
      "kind": "hold",
      "sequence": 34,
      "sha256": "3529ca6dc731e925c4f1f8a77045be491fdf8c596f6afd585084fef395f6bc22",
      "size": 3034,
      "stat_end": 26.5,
      "stat_start": 26.5
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 61,
      "kind": "end",
      "sequence": 62,
      "sha256": "77722c60ab120716630e2a775dc2d100a0fc0d8f2c7c331863673eb2ba3f1465",
      "size": 5540,
      "stat_end": 40.0,
      "stat_start": 40.0
    }
  ],
  "stop_proven": true,
  "trace": [
    {
      "event": "action_begin",
      "offset": 0.0
    },
    {
      "event": "action_end",
      "offset": 10.0
    },
    {
      "event": "pair",
      "offset": 11.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 12.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 13.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 14.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 15.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 16.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 17.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 18.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 19.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 20.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 21.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 22.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 23.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 24.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 25.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 26.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 27.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 28.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 29.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 30.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 31.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 32.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 33.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 34.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 35.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 36.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 37.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 38.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 39.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 40.0,
      "stage": "after"
    }
  ],
  "trusted": true
}
```

`R5_fault_applied_at_start_healthy_10s`

```json
{
  "end_sequence": 82,
  "errors": [],
  "exit": 0,
  "fault_sequence": 28,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 27,
  "post_markers": 27,
  "probe": "PASS",
  "reasons": [],
  "result": "PASS",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "kind": "pre",
      "sequence": 2,
      "sha256": "16415481f239d3569478c7697404b685f2771b85d1285e6cb334f0390ead4bbc",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 27,
      "kind": "fault",
      "sequence": 28,
      "sha256": "dbbf4715c19ad675289a9d983eaa3829d25b6830135a267ee61a7d645d2db370",
      "size": 2497,
      "stat_end": 13.0,
      "stat_start": 13.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 53,
      "kind": "hold",
      "sequence": 54,
      "sha256": "44b5f51a2d041e8a99551ee4a2284c1a7afba324b88c641714c323cda2f2bfa8",
      "size": 4824,
      "stat_end": 26.5,
      "stat_start": 26.5
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 81,
      "kind": "end",
      "sequence": 82,
      "sha256": "ebbcfef43dd17021554ef8e6861c9092bc3a1b8e438444a1705edb27928393c2",
      "size": 7330,
      "stat_end": 40.0,
      "stat_start": 40.0
    }
  ],
  "stop_proven": true,
  "trace": [
    {
      "event": "action_begin",
      "offset": 0.0
    },
    {
      "event": "pair",
      "offset": 1.0,
      "stage": "action"
    },
    {
      "event": "pair",
      "offset": 2.0,
      "stage": "action"
    },
    {
      "event": "pair",
      "offset": 3.0,
      "stage": "action"
    },
    {
      "event": "pair",
      "offset": 4.0,
      "stage": "action"
    },
    {
      "event": "pair",
      "offset": 5.0,
      "stage": "action"
    },
    {
      "event": "pair",
      "offset": 6.0,
      "stage": "action"
    },
    {
      "event": "pair",
      "offset": 7.0,
      "stage": "action"
    },
    {
      "event": "pair",
      "offset": 8.0,
      "stage": "action"
    },
    {
      "event": "pair",
      "offset": 9.0,
      "stage": "action"
    },
    {
      "event": "pair",
      "offset": 10.0,
      "stage": "action"
    },
    {
      "event": "action_end",
      "offset": 10.0
    },
    {
      "event": "pair",
      "offset": 11.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 12.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 13.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 14.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 15.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 16.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 17.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 18.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 19.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 20.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 21.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 22.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 23.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 24.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 25.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 26.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 27.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 28.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 29.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 30.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 31.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 32.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 33.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 34.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 35.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 36.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 37.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 38.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 39.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 40.0,
      "stage": "after"
    }
  ],
  "trusted": true
}
```

`R5_fault_applied_at_start_no_resume`

```json
{
  "end_sequence": 2,
  "errors": [
    "probe_gap"
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
    "probe_gap",
    "probe_post_fault_exit_missing",
    "probe_post_fault_marker_missing",
    "probe_hold_window_empty"
  ],
  "result": "INVALID",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "kind": "pre",
      "sequence": 2,
      "sha256": "f184f945aef8a5ea8e5ffdd3be45bcae15455b1e3fa1d1b4844ac94b730a2b31",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "kind": "fault",
      "sequence": 2,
      "sha256": "f184f945aef8a5ea8e5ffdd3be45bcae15455b1e3fa1d1b4844ac94b730a2b31",
      "size": 177,
      "stat_end": 13.0,
      "stat_start": 13.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "kind": "hold",
      "sequence": 2,
      "sha256": "f184f945aef8a5ea8e5ffdd3be45bcae15455b1e3fa1d1b4844ac94b730a2b31",
      "size": 177,
      "stat_end": 26.5,
      "stat_start": 26.5
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "kind": "end",
      "sequence": 2,
      "sha256": "f184f945aef8a5ea8e5ffdd3be45bcae15455b1e3fa1d1b4844ac94b730a2b31",
      "size": 177,
      "stat_end": 40.0,
      "stat_start": 40.0
    }
  ],
  "stop_proven": true,
  "trace": [
    {
      "event": "action_begin",
      "offset": 0.0
    },
    {
      "event": "action_end",
      "offset": 10.0
    }
  ],
  "trusted": true
}
```

`R5_fault_applied_at_start_silent_12s`

```json
{
  "end_sequence": 58,
  "errors": [],
  "exit": 0,
  "fault_sequence": 4,
  "guest_leak": false,
  "latch": false,
  "log_read": "exact",
  "persisted_leak": false,
  "post_exits": 27,
  "post_markers": 27,
  "probe": "PASS",
  "reasons": [],
  "result": "PASS",
  "samples": [
    {
      "exit_node_ok": true,
      "exit_sequence": 1,
      "kind": "pre",
      "sequence": 2,
      "sha256": "d5df8a0cbe1b7fa478479b7115042633943743c025f14ceeae351bf9acae0f0e",
      "size": 177,
      "stat_end": 0.0,
      "stat_start": 0.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 3,
      "kind": "fault",
      "sequence": 4,
      "sha256": "38bc0ce2c91987c784cf256d6fd71300c68fb4b688b062d09db38287c3a2f4ff",
      "size": 354,
      "stat_end": 13.0,
      "stat_start": 13.0
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 29,
      "kind": "hold",
      "sequence": 30,
      "sha256": "939ccf4a207a1df6eb35e344be15f2669e203529648030a4fa31ceb0edfaccd7",
      "size": 2676,
      "stat_end": 26.5,
      "stat_start": 26.5
    },
    {
      "exit_node_ok": true,
      "exit_sequence": 57,
      "kind": "end",
      "sequence": 58,
      "sha256": "cdada94f1a20e5637cba2afa4165cc91645dcf1afaa9268b3cd7613a7c61e4cb",
      "size": 5182,
      "stat_end": 40.0,
      "stat_start": 40.0
    }
  ],
  "stop_proven": true,
  "trace": [
    {
      "event": "action_begin",
      "offset": 0.0
    },
    {
      "event": "action_end",
      "offset": 12.0
    },
    {
      "event": "pair",
      "offset": 13.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 14.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 15.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 16.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 17.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 18.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 19.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 20.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 21.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 22.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 23.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 24.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 25.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 26.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 27.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 28.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 29.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 30.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 31.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 32.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 33.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 34.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 35.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 36.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 37.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 38.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 39.0,
      "stage": "after"
    },
    {
      "event": "pair",
      "offset": 40.0,
      "stage": "after"
    }
  ],
  "trusted": true
}
```

## R5-I1 confirmation with fault applied at action start

`action_injected.py` applies the real harness router fault immediately at +0, then models 10/12 s of action/postcondition latency before returning. Traffic is silent throughout this interval. Actual results above confirm **PASS** for both silent 10 s and 12 s variants, **PASS** for the healthy control, and **INVALID** for the no-resume control. Thus the finding also holds when the destructive transition precedes the entire silence interval, rather than following simulated action preparation.

### action_injected.py

```python
from pathlib import Path
exec(Path('/var/tmp/leaklab-m3r5-gpt/common.py').read_text())

def action_hook(stack, duration, silent=True, resume=True):
    original_start=rp.start_client_traffic
    original_fault=rp.run_router_fault
    h={}
    def start(client, **kw):
        result=original_start(client, **kw)
        h.update(client=client,t0=rp.time.monotonic(),g0=client.clock,stage='before')
        client.r4_trace=[]
        pair=client.probe_pair
        execute=client.execute
        def now(): return rp.time.monotonic()-h['t0']
        def guest_now(): return h['g0']+int(now())
        def probe_pair():
            client.clock=guest_now()
            client.r4_trace.append(dict(event='pair',offset=round(now(),4),stage=h['stage']))
            pair()
        def wrapped(program,args=(),**kw):
            command=args[-1] if args else ''
            if command.strip()=='date +%s':
                client.clock=guest_now()
                return tv.ExecResult(0,f'{client.clock}\n'.encode(),b'')
            return execute(program,args,**kw)
        client.probe_pair=probe_pair
        client.execute=wrapped
        return result
    def fault(*args,**kw):
        c=h['client']
        h['stage']='action'
        c.r4_trace.append(dict(event='action_begin',offset=round(rp.time.monotonic()-h['t0'],4)))
        if silent:
            c.hold_started_at=rp.time.monotonic()-0.001
            c.hold_plan=lambda offset:False
        result=original_fault(*args,**kw)
        rp.time.sleep(duration)
        c.r4_trace.append(dict(event='action_end',offset=round(rp.time.monotonic()-h['t0'],4)))
        h['stage']='after'
        if resume: c.hold_plan=None
        return result
    stack.enter_context(mock.patch.object(rp,'start_client_traffic',side_effect=start))
    stack.enter_context(mock.patch.object(rp,'run_router_fault',side_effect=fault))

for name,duration,silent,resume in [
 ('R5_fault_applied_at_start_silent_10s',10,True,True),
 ('R5_fault_applied_at_start_healthy_10s',10,False,True),
 ('R5_fault_applied_at_start_no_resume',10,True,False),
 ('R5_fault_applied_at_start_silent_12s',12,True,True),
]:
    phase(name,{},patches=lambda s,d=duration,q=silent,r=resume:action_hook(s,d,q,r))
```

## Final verification

Only this report was written in the repository; no tracked source changes. Both required suites ran exactly once. All reproducer commands completed. Scratch `/var/tmp/leaklab-m3r5-gpt` deleted after embedding the scripts and results. No privileged or network execution; no forbidden paths read; no Git writes.

Final HEAD drift: another actor advanced the shared checkout to `4b1e8c5f53b6490b129d709b07e6cc7a8c74255a` during this review. `git diff 9427346..HEAD -- tools/leak-lab/clientprobe.py tools/leak-lab/vm/run_phase.py tools/leak-lab/vm/test_vm.py tools/leak-lab/test_leak_lab.py` is empty; the reviewed implementation and test files remain identical to the requested target. I performed no Git writes.

Verdict: FAIL

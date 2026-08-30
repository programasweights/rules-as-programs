from __future__ import annotations

from experiments.eacl2027.run_operational import (
    _python_executable_basename,
    measure_daemon_unavailable,
    measure_duplicate_admission,
    measure_hook_handoff,
)


def test_python_provenance_does_not_expose_local_path():
    assert (
        _python_executable_basename("/Users/researcher/private-env/bin/python3.12")
        == "python3.12"
    )


def test_hook_handoff_uses_isolated_socket_mock(tmp_path):
    result = measure_hook_handoff(
        tmp_path,
        repetitions=2,
        warmups=1,
    )

    assert result["measured_invocations"] == 2
    assert result["warmup_invocations_excluded"] == 1
    assert result["validated_mock_requests"] == 3
    assert len(result["samples"]) == 2
    for metric in result["metrics"].values():
        assert metric["count"] == 2
        assert metric["minimum"] >= 0


def test_daemon_unavailable_probe_is_fail_open_and_does_not_spawn(tmp_path):
    result = measure_daemon_unavailable(tmp_path, repetitions=3)

    assert result["return_codes_all_zero"]
    assert result["outputs_all_empty_json_objects"]
    assert result["daemon_spawn_attempts"] == 3


def test_duplicate_admission_scenarios_are_deterministic(tmp_path):
    result = measure_duplicate_admission(
        tmp_path,
        concurrency=8,
        concurrency_trials=3,
    )
    scenarios = result["scenarios"]

    assert scenarios["identical_global_and_project_delivery_within_ttl"][
        "admission_outcomes"
    ] == [True, False]
    assert scenarios["identical_delivery_after_ttl"]["admission_outcomes"] == [
        True,
        True,
    ]
    assert scenarios["stop_dual_projection_from_two_hook_layers"][
        "admission_outcomes"
    ] == [True, True, False, False]
    assert scenarios["distinct_tool_use_ids"]["admission_outcomes"] == [True, True]
    assert scenarios["concurrent_identical_delivery"]["admitted_per_trial"] == [1, 1, 1]

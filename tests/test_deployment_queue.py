from rules_as_programs.core.deployment_queue import (
    CANCELLABLE_DEPLOYMENT_STATUSES,
    DeploymentQueueStore,
    OPTIMIZATION_KIND,
    VALIDATION_KIND,
)


def test_deployment_queue_persists_and_cancels(tmp_path):
    path = tmp_path / "queue.json"
    store = DeploymentQueueStore(path)
    store.put({
        "id": "queue",
        "rule_id": "rule",
        "status": "waiting_for_build",
        "source_hash": "source",
    })

    reopened = DeploymentQueueStore(path)
    active = reopened.active_for_rule("rule")
    cancelled = reopened.cancel("queue", "Draft changed.")

    assert active["source_hash"] == "source"
    assert cancelled["status"] == "cancelled"
    assert reopened.active_for_rule("rule") is None
    assert reopened.latest_for_rule("rule")["error"] == "Draft changed."


def test_optimization_jobs_do_not_replace_deployment_status(tmp_path):
    store = DeploymentQueueStore(tmp_path / "queue.json")
    store.put({
        "id": "deploy",
        "rule_id": "rule",
        "status": "checking",
    })
    store.put({
        "id": "optimize",
        "kind": OPTIMIZATION_KIND,
        "rule_id": "rule",
        "status": "building",
    })

    assert store.active_for_rule("rule")["id"] == "deploy"
    assert store.active_for_rule(
        "rule", kind=OPTIMIZATION_KIND)["id"] == "optimize"
    assert {item["id"] for item in store.pending()} == {
        "deploy", "optimize"}


def test_validation_jobs_have_independent_rule_status(tmp_path):
    store = DeploymentQueueStore(tmp_path / "queue.json")
    store.put({
        "id": "deploy",
        "rule_id": "rule",
        "status": "building",
    })
    store.put({
        "id": "validate",
        "kind": VALIDATION_KIND,
        "rule_id": "rule",
        "status": "validating",
    })

    assert store.active_for_rule("rule")["id"] == "deploy"
    assert store.active_for_rule(
        "rule", kind=VALIDATION_KIND)["id"] == "validate"


def test_queue_transitions_and_cancellation_are_atomic(tmp_path):
    store = DeploymentQueueStore(tmp_path / "queue.json")
    store.put({
        "id": "deploy",
        "rule_id": "rule",
        "status": "building",
    })

    cancelled = store.cancel(
        "deploy",
        expected_statuses=CANCELLABLE_DEPLOYMENT_STATUSES,
    )
    stale_worker = store.compare_and_update(
        "deploy", {"building"}, status="checking")

    assert cancelled["status"] == "cancelled"
    assert stale_worker is None
    assert store.get("deploy")["status"] == "cancelled"


def test_committing_deployment_cannot_be_cancelled(tmp_path):
    store = DeploymentQueueStore(tmp_path / "queue.json")
    store.put({
        "id": "deploy",
        "rule_id": "rule",
        "status": "deploying",
    })

    cancelled = store.cancel(
        "deploy",
        expected_statuses=CANCELLABLE_DEPLOYMENT_STATUSES,
    )

    assert cancelled is None
    assert store.get("deploy")["status"] == "deploying"

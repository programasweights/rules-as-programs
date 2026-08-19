from rules_as_programs.core.deployment_queue import DeploymentQueueStore


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

from core.events import DetectionEvent, Severity
from core.persistence import BlockStore
from core.pipeline import EventPipeline
from core.whitelist import WhitelistManager


class StubBlocker:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def block(self, ip):
        self.calls.append(ip)
        return self.result


def event(ip="10.0.0.9"):
    return DetectionEvent("SYN_FLOOD", ip, "10.0.0.2", Severity.CRITICAL, 1.0)


def store_and_whitelist(tmp_path):
    return BlockStore(str(tmp_path / "blocked.json")), WhitelistManager(str(tmp_path / "whitelist.txt"))


def test_pipeline_does_not_persist_if_all_blockers_fail(tmp_path):
    store, whitelist = store_and_whitelist(tmp_path)
    pipeline = EventPipeline(whitelist, store, StubBlocker(False), StubBlocker(False))

    assert pipeline.process(event()) is False
    assert store.all() == []


def test_pipeline_persists_enforcement_statuses(tmp_path):
    store, whitelist = store_and_whitelist(tmp_path)
    pipeline = EventPipeline(whitelist, store, StubBlocker(True), StubBlocker(False))

    assert pipeline.process(event()) is True
    records = store.all()
    assert records[0]["firewall_blocked"] is True
    assert records[0]["victim_blocked"] is False


def test_pipeline_skips_whitelisted_and_duplicate_ips(tmp_path):
    store, whitelist = store_and_whitelist(tmp_path)
    whitelist.add("10.0.0.8")
    firewall = StubBlocker(True)
    victim = StubBlocker(True)
    pipeline = EventPipeline(whitelist, store, firewall, victim)

    assert pipeline.process(event("10.0.0.8")) is False
    assert pipeline.process(event("10.0.0.9")) is True
    assert pipeline.process(event("10.0.0.9")) is False
    assert firewall.calls == ["10.0.0.9"]

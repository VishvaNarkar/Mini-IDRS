from scapy.layers.inet import IP, TCP

from core.events import Severity
from plugins.base import DetectionContext
from plugins.ssh_brute_force import SshBruteForceDetector
from plugins.syn_flood import SynFloodDetector
from plugins.xmas_scan import XmasScanDetector


def ctx(**overrides):
    base = DetectionContext(
        victim_ip="10.0.0.2",
        monitor_ip="10.0.0.1",
        thresholds={
            "syn_flood": {"threshold": 3, "window_seconds": 5},
            "ssh_brute_force": {"threshold": 2, "window_seconds": 60},
        },
        whitelist=set(),
    )
    for key, value in overrides.items():
        setattr(base, key, value)
    return base


def test_syn_flood_triggers_at_threshold():
    detector = SynFloodDetector()
    packet = IP(src="10.0.0.9", dst="10.0.0.2") / TCP(dport=80, flags="S")

    assert detector.handle_packet(packet, ctx()) is None
    assert detector.handle_packet(packet, ctx()) is None
    event = detector.handle_packet(packet, ctx())

    assert event is not None
    assert event.attack == "SYN_FLOOD"
    assert event.severity == Severity.CRITICAL
    assert event.details["packet_count"] == 3


def test_syn_flood_skips_whitelist():
    detector = SynFloodDetector()
    packet = IP(src="10.0.0.9", dst="10.0.0.2") / TCP(dport=80, flags="S")

    for _ in range(3):
        assert detector.handle_packet(packet, ctx(whitelist={"10.0.0.9"})) is None


def test_xmas_scan_detects_exact_flags():
    detector = XmasScanDetector()
    packet = IP(src="10.0.0.9", dst="10.0.0.2") / TCP(flags="FPU")

    event = detector.handle_packet(packet, ctx())

    assert event is not None
    assert event.attack == "XMAS_SCAN"
    assert event.details == {"flags": "0x29"}


def test_ssh_brute_force_triggers_on_completed_handshakes():
    detector = SshBruteForceDetector()
    context = ctx()

    for sport in (41000, 41001):
        syn = IP(src="10.0.0.9", dst="10.0.0.2") / TCP(sport=sport, dport=22, flags="S")
        syn_ack = IP(src="10.0.0.2", dst="10.0.0.9") / TCP(sport=22, dport=sport, flags="SA")
        ack = IP(src="10.0.0.9", dst="10.0.0.2") / TCP(sport=sport, dport=22, flags="A")
        assert detector.handle_packet(syn, context) is None
        assert detector.handle_packet(syn_ack, context) is None
        event = detector.handle_packet(ack, context)

    assert event is not None
    assert event.attack == "SSH_BRUTE_FORCE"
    assert event.details["handshake_count"] == 2

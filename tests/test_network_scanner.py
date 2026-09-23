import argparse
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import network_scanner as ns


def reply(ip, mac):
    # srp() hands back (sent, received) pairs; we only read psrc/hwsrc off the reply
    return (None, SimpleNamespace(psrc=ip, hwsrc=mac))


@pytest.fixture
def fake_net(monkeypatch):
    calls = {}

    def fake_srp(packet, timeout, iface, verbose):
        calls.update(timeout=timeout, iface=iface)
        answered = [reply("192.168.1.10", "aa:aa:aa:aa:aa:aa"), reply("192.168.1.9", "bb:bb:bb:bb:bb:bb")]
        return answered, []

    monkeypatch.setattr(ns, "srp", fake_srp)
    monkeypatch.setattr(ns, "require_root", lambda: None)
    return calls


@pytest.mark.parametrize("target, expected", [
    ("192.168.1.1/24", "192.168.1.0/24"),
    ("10.0.0.5", "10.0.0.5/32"),
])
def test_parse_target_accepts_ipv4(target, expected):
    assert ns.parse_target(target) == expected


@pytest.mark.parametrize("target", ["banana", "300.1.1.1", "fe80::1/64"])
def test_parse_target_rejects_garbage_and_ipv6(target):
    with pytest.raises(argparse.ArgumentTypeError):
        ns.parse_target(target)


def test_target_is_required():
    with pytest.raises(SystemExit):
        ns.get_arguments([])


def test_require_root_exits_for_normal_users(monkeypatch):
    monkeypatch.setattr(ns.os, "geteuid", lambda: 1000, raising=False)
    with pytest.raises(SystemExit, match="need root"):
        ns.require_root()


def test_scan_sorts_numerically_and_passes_flags(fake_net):
    result = ns.scan("192.168.1.0/24", timeout=1.5, iface="eth0")
    assert [c["ip"] for c in result] == ["192.168.1.9", "192.168.1.10"]
    assert fake_net == {"timeout": 1.5, "iface": "eth0"}


def test_empty_network_message(capsys):
    ns.print_result([])
    assert "Nobody answered" in capsys.readouterr().out


def test_json_output(fake_net, capsys):
    ns.main(["-t", "192.168.1.0/24", "--json"])
    hosts = json.loads(capsys.readouterr().out)
    assert hosts[0] == {"ip": "192.168.1.9", "mac": "bb:bb:bb:bb:bb:bb"}


def test_table_output(fake_net, capsys):
    ns.main(["-t", "192.168.1.0/24"])
    out = capsys.readouterr().out
    assert out.index("192.168.1.9") < out.index("192.168.1.10")

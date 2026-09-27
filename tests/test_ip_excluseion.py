"""Exercise exclusions through the public target-processing API without network access."""

from types import SimpleNamespace

import netifaces
import pytest

from nxc.parsers import ip


@pytest.fixture(autouse=True)
def isolated_config(monkeypatch):
    monkeypatch.setattr(ip, "exclude_hosts", [])
    monkeypatch.setattr(ip, "skip_self", False)


def target_args(targets, exclusions=None, *, skip_self=False):
    return SimpleNamespace(target=targets, exclude_hosts=exclusions, skip_self=skip_self, protocol="smb")


@pytest.mark.parametrize(("exclusions", "expected"), [
    (None, ["192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3"]),
    ([], ["192.0.2.0", "192.0.2.1", "192.0.2.2", "192.0.2.3"]),
    (["192.0.2.1"], ["192.0.2.0", "192.0.2.2", "192.0.2.3"]),
    (["192.0.2.0/31"], ["192.0.2.2", "192.0.2.3"]),
    (["192.0.2.1-192.0.2.2"], ["192.0.2.0", "192.0.2.3"]),
    (["192.0.2.1-2"], ["192.0.2.0", "192.0.2.3"]),
    (["192.0.2.0/30"], []),
    (["192.0.2.1", "192.0.2.1", "192.0.2.2"], ["192.0.2.0", "192.0.2.3"]),
])
def test_exclusion_formats(exclusions, expected):
    assert ip.process_targets(target_args(["192.0.2.0/30"], exclusions)) == expected


def test_ipv6_exclusions():
    assert ip.process_targets(target_args(["2001:db8::/126"], ["2001:db8::1-2"])) == ["2001:db8::", "2001:db8::3"]


def test_config_and_cli_exclusions_do_not_leak_between_runs(monkeypatch):
    configured = ["192.0.2.1"]
    monkeypatch.setattr(ip, "exclude_hosts", configured)
    targets = ["192.0.2.1-3"]
    assert ip.process_targets(target_args(targets, ["192.0.2.2"])) == ["192.0.2.3"]
    assert configured == ["192.0.2.1"]
    assert ip.process_targets(target_args(targets)) == ["192.0.2.2", "192.0.2.3"]


def test_target_and_exclusion_files(tmp_path):
    targets = tmp_path / "targets.txt"
    targets.write_text("192.0.2.1-3\n2001:db8::1\n")
    exclusions = tmp_path / "excluded.txt"
    exclusions.write_text("192.0.2.1\n2001:db8::1\n")
    assert ip.process_targets(target_args([str(targets)], [str(exclusions)])) == ["192.0.2.2", "192.0.2.3"]


@pytest.mark.parametrize("excluded", ["example.test", "999.0.0.1"])
def test_invalid_exclusion_is_rejected(excluded):
    with pytest.raises(SystemExit) as exc:
        ip.process_targets(target_args(["192.0.2.1"], [excluded]))
    assert exc.value.code == 1


@pytest.mark.parametrize("answer", ["y", "yes", ""])
def test_hostname_targets_prompt_once(monkeypatch, answer):
    prompts = []

    def accept(prompt):
        prompts.append(prompt)
        return answer

    monkeypatch.setattr("builtins.input", accept)
    assert ip.process_targets(target_args(["one.test", "two.test", "192.0.2.1"], ["192.0.2.1"])) == ["one.test", "two.test"]
    assert len(prompts) == 1


def test_hostname_prompt_declined(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda prompt: "n")
    with pytest.raises(SystemExit) as exc:
        ip.process_targets(target_args(["example.test"], ["192.0.2.1"]))
    assert exc.value.code == 1


@pytest.mark.parametrize(("configured", "requested"), [(True, False), (False, True), (True, True)])
def test_skip_self_from_config_or_cli(monkeypatch, configured, requested):
    monkeypatch.setattr(ip, "skip_self", configured)
    monkeypatch.setattr(ip, "get_local_ips", lambda: {"192.0.2.1", "2001:db8::1"})
    assert ip.process_targets(target_args(["192.0.2.1-2", "2001:db8::1"], skip_self=requested)) == ["192.0.2.2"]


def test_get_local_ips_collects_all_interfaces(monkeypatch):
    monkeypatch.setattr(netifaces, "interfaces", lambda: ["lo0", "eth0", "wlan0"])
    addresses = {
        "eth0": {netifaces.AF_INET: [{"addr": "192.0.2.1"}, {"addr": "127.0.0.1"}, {"addr": "169.254.1.1"}], netifaces.AF_INET6: [{"addr": "2001:db8::1"}, {"addr": "::1"}, {"addr": "fe80::1%eth0"}]},
        "wlan0": {netifaces.AF_INET: [{"addr": "192.0.2.2"}, {}]},
    }
    monkeypatch.setattr(netifaces, "ifaddresses", addresses.__getitem__)
    assert ip.get_local_ips() == {"192.0.2.1", "192.0.2.2", "2001:db8::1"}


def test_get_local_ips_no_usable_addresses(monkeypatch):
    monkeypatch.setattr(netifaces, "interfaces", lambda: ["lo0", "eth0"])
    monkeypatch.setattr(netifaces, "ifaddresses", lambda interface: {netifaces.AF_INET: [{"addr": "169.254.1.1"}]})
    assert ip.get_local_ips() == set()

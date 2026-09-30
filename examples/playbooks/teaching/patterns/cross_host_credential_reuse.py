"""Cross-host credential reuse: log in on one host, reuse that stored login on another.

Authenticate on the source host, take smb.credential, then open a session on an
--allow-target host with host.at(other).smb(credential=...) and read its admin/shares.

nxc playbook 10.60.0.11 examples/playbooks/teaching/patterns/cross_host_credential_reuse.py \
    -u jon.snow -p iknownothing -d north.sevenkingdoms.local --allow-target 10.60.0.22
"""

from dataclasses import dataclass, field


@dataclass
class ReuseVerdict:
    source_credential: object = None
    reused_admin: bool | None = None
    shares: list[str] = field(default_factory=list)
    evidence: list[int] = field(default_factory=list)


def run(host):
    host.defaults(stop_on_error=False)
    data = ReuseVerdict()
    with host.evidence() as ev:
        smb = host.smb()  # uses CLI -u/-p/-d on the source host
        data.source_credential = smb.credential  # CredentialRef to reuse, or None
        if not smb.authenticated or smb.credential is None:
            data.evidence = list(ev.indices)
            return host.finding("cross_host_credential_reuse", ok=False, data=data)

        other = host.at("10.60.0.22").smb(credential=smb.credential)  # needs --allow-target
        data.reused_admin = other.admin  # True / False / None on the second host
        if other.ok:
            data.shares = [record.name for record in other.shares().data.shares]

    data.evidence = list(ev.indices)
    return host.finding("cross_host_credential_reuse", ok=other.authenticated, data=data)

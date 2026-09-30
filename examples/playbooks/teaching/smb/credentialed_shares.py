"""Credentialed SMB: log in with CLI creds, read admin state, list shares and password policy.

nxc playbook 10.60.0.11 examples/playbooks/teaching/smb/credentialed_shares.py \
    -u jon.snow -p iknownothing -d north.sevenkingdoms.local
"""

from dataclasses import dataclass, field


@dataclass
class CredentialedSMB:
    authenticated: bool = False
    admin: bool | None = None
    shares: list[str] = field(default_factory=list)
    min_password_length: int | str | None = None
    evidence: list[int] = field(default_factory=list)


def run(host):
    host.defaults(stop_on_error=False)
    data = CredentialedSMB()
    with host.evidence() as steps:
        smb = host.smb()  # uses CLI -u/-p/-d
        data.authenticated = smb.authenticated
        data.admin = smb.admin  # True / False / None
        if not smb.authenticated:
            data.evidence = list(steps.indices)
            return host.finding("credentialed_shares", ok=False, data=data)

        shares = smb.shares()
        data.shares = [record.name for record in shares.data.shares]
        data.min_password_length = smb.pass_pol().data.min_password_length

        data.evidence = list(steps.indices)
        return host.finding("credentialed_shares", ok=shares.ok, data=data)

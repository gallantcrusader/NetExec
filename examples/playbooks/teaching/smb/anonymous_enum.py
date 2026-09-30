"""Anonymous / null-session SMB: connect with no credentials, then branch.

Enumerate shares and users only when the null session is actually allowed to
list shares; a locked-down host is a reachable-but-not-this NEGATIVE, not a failure.

    nxc playbook 10.60.0.10 examples/playbooks/teaching/smb/anonymous_enum.py
"""

from dataclasses import dataclass, field


@dataclass
class AnonEnum:
    anonymous_access: bool = False
    shares: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    evidence_indices: list[int] = field(default_factory=list)


def run(host):
    host.defaults(stop_on_error=False)
    data = AnonEnum()
    with host.evidence() as steps:
        smb = host.smb(anonymous=True)
        if not smb.ok:
            return host.finding("smb_anonymous_enum", ok=False, data=data)

        shares = smb.shares()
        data.anonymous_access = shares.ok and shares.data.anonymous_access
        if not data.anonymous_access:
            data.evidence_indices = list(steps.indices)
            return host.finding("smb_anonymous_enum", ok=False, data=data)

        data.shares = [record.name for record in shares.data.shares]
        users = smb.users()
        data.users = [user.username for user in users.data.users] if users.ok else []
        data.evidence_indices = list(steps.indices)
        return host.finding("smb_anonymous_enum", ok=True, data=data)

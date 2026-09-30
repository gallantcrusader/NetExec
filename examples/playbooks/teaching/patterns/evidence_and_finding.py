"""Evidence + verdict: wrap steps in host.evidence(), then record a host.finding().

The evidence block auto-collects each recorded step's index into ev.indices; the
verdict carries a small @dataclass as data and passes ev.indices in its inputs.

nxc playbook 10.60.0.11 examples/playbooks/teaching/patterns/evidence_and_finding.py -u jon.snow -p iknownothing -d north.sevenkingdoms.local
"""

from dataclasses import dataclass


@dataclass
class AccessVerdict:
    authenticated: bool
    admin: bool | None
    shares: int


def run(host):
    host.defaults(stop_on_error=False)
    with host.evidence() as ev:
        smb = host.smb()
        listing = smb.shares()
    verdict = AccessVerdict(
        authenticated=smb.authenticated,
        admin=smb.admin,
        shares=len(listing.data.shares) if listing.ok else 0,
    )
    host.finding("smb_access", ok=smb.authenticated, data=verdict, inputs={"evidence": ev.indices})

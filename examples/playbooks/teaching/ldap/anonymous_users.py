"""Anonymous LDAP recon: bind with no credentials and, only when that succeeds,
enumerate users plus their descriptions (where passwords are often stashed).

    nxc playbook 10.60.0.10 examples/playbooks/teaching/ldap/anonymous_users.py
"""

from dataclasses import dataclass


@dataclass
class AnonymousRecon:
    anonymous_bind: bool
    users: int = 0
    described: int = 0


def run(host):
    host.defaults(stop_on_error=False)

    ldap = host.ldap(anonymous=True)
    if not ldap.ok:
        # Reachable but the directory refused an unauthenticated bind: a branchable
        # "not this" outcome, so record a NEGATIVE finding and stop here.
        return host.finding("ldap_anonymous_users", ok=False, data=AnonymousRecon(anonymous_bind=False))

    users = ldap.users()
    described = ldap.module("get-desc-users")
    data = AnonymousRecon(
        anonymous_bind=True,
        users=len(users.data.users),
        described=len(described.data.users) if described.ok else 0,
    )
    return host.finding("ldap_anonymous_users", ok=data.users > 0, data=data)

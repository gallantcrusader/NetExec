"""Verify a GOAD Domain Admin candidate on its domain controller.

The initial domain credential is saved by NetExec's LDAP login and reused by
reference for SMB on the same DC. This only authenticates and checks access.
"""

import json
from dataclasses import dataclass, field
from pathlib import Path

from nxc.paths import NXC_PATH
from nxc.playbooks.results import ActionResult, CredentialRef, ResultStatus


@dataclass
class DomainAdminEndpoint:
    user: str
    domain: str
    credential: CredentialRef | None = None
    principal_sid: str | None = None
    domain_admins_sid: str | None = None
    computed_membership: bool = False
    smb_authenticated: bool = False
    smb_admin_privileges: bool | None = None
    admin_check_error: str | None = None
    evidence_indices: list[int] = field(default_factory=list)
    reached_tier_zero_host: bool = False
    reason: str | None = None
    transitions_executed: bool = False


def run(host):
    graph = json.loads((Path(NXC_PATH) / "playbooks" / "goad-membership-graph.json").read_text(encoding="utf-8"))
    controllers = {"10.60.0.10": "sevenkingdoms.local", "10.60.0.11": "north.sevenkingdoms.local", "10.60.0.12": "essos.local"}
    if host.target not in controllers or graph["unresolved"] or graph["verified_count"] != graph["source_count"]:
        raise ValueError("Start on a configured DC with a fully reconciled GOAD group graph")
    domain = controllers[host.target]
    data = DomainAdminEndpoint("", domain)

    def finish(reason=None):
        data.reason = reason
        status = ResultStatus.FAILED if data.admin_check_error else ResultStatus.SUCCESS if data.reached_tier_zero_host else ResultStatus.NEGATIVE
        host.record(ActionResult("playbook", "goad_domain_admin_endpoint", host.target, status, data, error=data.admin_check_error, inputs={"principal": data.user, "domain": domain}), stop_on_error=False)

    ldap = host.ldap()
    data.evidence_indices.append(len(host.run.results) - 1)
    data.user = str(getattr(ldap.connection, "username", ""))
    if not ldap.ok or not ldap.result.data.authenticated:
        finish("Directory login was not established")
        return
    principal = data.user
    paths = [path for path in graph["domain_admin_membership_paths"] if path["user_domain"] == domain and path["target_domain"] == domain and path["user"].casefold() == principal.casefold()]
    if len(paths) != 1:
        raise ValueError("The authenticated account must have one verified same-domain Domain Admin membership path")
    path = paths[0]
    data.credential = ldap.result.data.credential
    data.principal_sid = path["user_sid"]
    data.domain_admins_sid = path["target_sid"]

    if data.credential is None:
        finish("LDAP login did not store a reusable database credential reference")
        return
    token = ldap.module("token-groups", principal=principal, stop_on_error=False)
    data.evidence_indices.append(len(host.run.results) - 1)
    if token.status is ResultStatus.FAILED or not token.data.groups_returned:
        finish("Computed domain group SIDs were unavailable")
        return
    data.computed_membership = token.data.principal_sid == data.principal_sid and data.domain_admins_sid in token.data.directory_sids
    if not data.computed_membership:
        finish("Computed Domain Admin membership did not match the observed graph")
        return
    smb = host.smb(credential=data.credential)
    data.evidence_indices.append(len(host.run.results) - 1)
    data.smb_authenticated = smb.ok and smb.result.data.authenticated
    if not data.smb_authenticated:
        finish("Stored directory credential did not establish SMB authentication on the DC")
        return
    data.smb_admin_privileges = smb.result.data.admin_privileges
    data.admin_check_error = smb.result.data.admin_check_error
    data.reached_tier_zero_host = data.smb_admin_privileges is True
    finish(None if data.reached_tier_zero_host else "SMB authentication succeeded but the admin check did not confirm DC administrator access")

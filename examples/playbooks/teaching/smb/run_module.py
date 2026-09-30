"""Run an SMB module and read its ModuleResult.

smb.module(...) always returns a ModuleResult: iterate it for the per-run
ActionResult(s), then read res.ok and res.data.<field>. Here spider_plus runs
read-only (DOWNLOAD_FLAG=False) and we report each readable share it found.

nxc playbook 10.60.0.22 examples/playbooks/teaching/smb/run_module.py \
    -u jon.snow -p iknownothing -d north.sevenkingdoms.local
"""

from dataclasses import dataclass, field


@dataclass
class SpiderEvidence:
    shares: list[str] = field(default_factory=list)
    readable_shares: list[str] = field(default_factory=list)


def run(host):
    host.defaults(stop_on_error=False)
    smb = host.smb()
    if not smb.ok:
        return host.finding("smb_run_module", ok=False)

    data = SpiderEvidence()
    m = smb.module("spider_plus", download_flag=False)
    for res in m:  # ModuleResult is iterable; spider_plus emits one result here
        if res.ok:
            data.shares = res.data.shares
            data.readable_shares = res.data.readable_shares

    return host.finding("smb_run_module", ok=m.ok and bool(data.readable_shares), data=data)

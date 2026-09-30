"""stop_on_error defaults: host.defaults(stop_on_error=False) lets probe steps keep going.

An explicit per-call stop_on_error=True always wins over that host default, so one
critical step still halts the workflow while the recon probes around it do not.

nxc playbook 10.60.0.11 examples/playbooks/teaching/patterns/stop_on_error_defaults.py \
    -u jon.snow -p iknownothing -d north.sevenkingdoms.local
"""


def run(host):
    host.defaults(stop_on_error=False)  # probe-style default: failures record and continue

    smb = host.smb()
    smb.shares()  # probe: inherits the False default, so a failure is recorded, not fatal
    smb.disks()   # another probe under the same forgiving default

    # A single critical step opts back in: an explicit per-call value always wins over
    # the host default, so a failure here raises and stops the workflow.
    pol = smb.pass_pol(stop_on_error=True)

    return host.finding("stop_on_error_defaults", ok=pol.ok)

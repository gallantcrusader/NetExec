"""Run an LDAP module and read its typed ModuleResult.

ldap.module(...) always returns a ModuleResult; for a single-result module its
.ok and .data proxy straight to that one result, so m.data.quota is the module's
own typed field (here MachineAccountQuota, the number of machines a user may join).

    nxc playbook 10.60.0.10 examples/playbooks/teaching/ldap/run_module.py -u tywin.lannister -p powerkingftw135 -d sevenkingdoms.local
"""


def run(host):
    host.defaults(stop_on_error=False)

    ldap = host.ldap()
    if not ldap.authenticated:
        return host.finding("machine_account_quota", ok=False)

    m = ldap.module("maq")           # ModuleResult wrapping one ActionResult
    if not m.ok:
        return host.finding("machine_account_quota", ok=False)

    # m.data proxies to the single result's dataclass; read its typed field.
    quota = m.data.quota
    return host.finding("machine_account_quota", ok=quota > 0, data=m.data, inputs={"quota": quota})

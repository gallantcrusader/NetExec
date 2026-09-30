"""Authenticated LDAP query: guard on the login, then read .rows and .one().

ldap.query(query=[filter, "space separated attrs"]) returns an ActionResult;
.rows is a list[dict] (one dict per object) and .one() is the single row or raises.

    nxc playbook 10.60.0.11 examples/playbooks/teaching/ldap/authenticated_query.py \
        -u jon.snow -p iknownothing -d north.sevenkingdoms.local
"""


def run(host):
    host.defaults(stop_on_error=False)

    ldap = host.ldap()  # uses CLI -u/-p/-d
    if not ldap.authenticated:
        return host.finding("ldap_authenticated_query", ok=False)

    domain = ldap.query(query=["(objectClass=domain)", "name"]).one()
    users = ldap.query(query=["(objectClass=user)", "sAMAccountName"]).rows

    host.finding(
        "ldap_authenticated_query",
        ok=True,
        inputs={"domain": domain.get("name"), "user_count": len(users)},
    )

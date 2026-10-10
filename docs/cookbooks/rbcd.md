# Resource-based constrained delegation

The LDAP `rbcd` module reads the allow ACEs in a target account's `msDS-AllowedToActOnBehalfOfOtherIdentity` security descriptor. `TARGET` and `SOURCE` are exact `sAMAccountName` values. The module never chooses a target from a partial match.

```sh
nxc ldap dc.example.test -u analyst -p 'PASSWORD' -M rbcd -o TARGET=fileserver$
nxc ldap dc.example.test -u analyst -p 'PASSWORD' -M rbcd -o TARGET=fileserver$ SOURCE=svc_app ACTION=read
```

The first command lists all allow ACE SIDs. The second reports whether the resolved source SID appears in that list. `ActionResult.data` includes the target DN and SPNs, source SID, and before/after SID lists. An ACE is directory evidence, not proof that a KDC will issue a delegated ticket or that the resulting service login has administrator rights.

To change one grant, explicitly choose `ACTION=add` or `ACTION=remove`. `TARGET_DN` can assert the already resolved target DN before a write. The module preserves other ACEs and rereads the descriptor to confirm the selected source SID's presence or absence.

```sh
nxc ldap dc.example.test -u operator -p 'PASSWORD' -M rbcd \
  -o TARGET=fileserver$ TARGET_DN='CN=FILESERVER,CN=Computers,DC=example,DC=test' SOURCE=svc_app ACTION=add
nxc ldap dc.example.test -u operator -p 'PASSWORD' -M rbcd \
  -o TARGET=fileserver$ SOURCE=svc_app ACTION=remove
```

`data.modified` means LDAP acknowledged the change. `data.completed` means a follow-up LDAP read confirmed it. For a usable delegation chain, authenticate as the source account and use the separate `delegation` module to request an impersonated ticket for one explicit SPN, then verify service access with that ticket. The NetExec workspace database remains the source for account credentials; `rbcd` neither creates nor stores passwords.

# LDAP delegation module

`delegation` uses an authenticated NetExec LDAP connection to list classic constrained, resource-based constrained (RBCD), and unconstrained delegation. Each result names the delegating principal, its type, the target account when it can be resolved, and the allowed service principal (SPN) when one is defined. Results are structured for Python playbooks.

## List delegation

```sh
nxc ldap dc.example.test -u analyst -p 'PASSWORD' -M delegation
nxc ldap dc.example.test -u analyst -p 'PASSWORD' -M delegation -o ACCOUNT=svc_web
```

Enumeration is the default. `ACCOUNT` limits displayed and structured results to one delegating account. Unconstrained delegation has no fixed target SPN. Classic constrained delegation without protocol transition requires an existing forwardable user ticket; an account with protocol transition or an RBCD grant can request S4U tickets for eligible users.

## Request a ticket

Log in as the account allowed to delegate, then provide the user to impersonate:

```sh
nxc ldap dc.example.test -u svc_web -p 'PASSWORD' -M delegation -o USER=alice
```

The module picks the sole allowed SPN. When several aliases point to one target, it prefers that target’s full `cifs/` hostname. Specify an SPN when the choice is ambiguous:

```sh
nxc ldap dc.example.test -u svc_web -p 'PASSWORD' -M delegation -o USER=alice SPN=cifs/files.example.test
```

NetExec requests S4U2Self and S4U2Proxy using the login account's existing password, hash, AES key, or Kerberos cache. The KDC decides whether the account may impersonate the requested user and delegate to the SPN. The resulting ccache is saved under `NXC_PATH/delegation/` by default. Use `OUTPUT=/absolute/path/ticket.ccache` to choose a path. Set `KRB5CCNAME` to the saved file to use it with other Kerberos-aware tools.

The module returns an `ActionResult` whose `data.delegations` is a list of typed delegation records; a successful ticket request also sets `data.ccache` and `data.expires_at` (Unix UTC seconds from the ccache ticket end time) and returns a `kerberos_ccache` artifact. It rejects a ticket already expired at issuance. It does not modify directory objects.

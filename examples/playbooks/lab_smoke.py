"""Read-only SMB/LDAP integration checks; supply credentials through the CLI."""


def run(host):
    anonymous = host.smb(anonymous=True, stop_on_error=False)
    if anonymous.ok:
        anonymous.shares(stop_on_error=False)

    smb = host.smb(stop_on_error=False)
    if not smb.ok or not smb.result.data.authenticated:
        return
    assert host.smb() is smb, "SMB session was not reused"
    smb.shares()
    smb.pass_pol()
    credential = smb.result.data.credential
    assert credential is not None, "Successful password login has no database reference"

    ldap = host.ldap(credential=credential, stop_on_error=False)
    if not ldap.ok:
        return
    assert host.ldap(credential=credential) is ldap, "LDAP session was not reused"
    ldap.query(query=["(objectClass=domain)", "distinguishedName name"])
    ldap.module("maq")
    ldap.module("get-desc-users")

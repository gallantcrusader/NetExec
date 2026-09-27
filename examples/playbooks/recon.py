"""Example: branch on anonymous SMB and LDAP access, then use supplied credentials."""


def run(host):
    smb = host.smb(anonymous=True)
    if smb.ok:
        shares = smb.shares(stop_on_error=False)
        if shares.ok and shares.data.shares:
            smb.users(stop_on_error=False)
            smb.pass_pol(stop_on_error=False)
            smb.module("spider_plus", download_flag=True, stop_on_error=False)

    named_smb = host.smb()
    stored_credential = named_smb.result.data.credential if named_smb.ok else None

    ldap = host.ldap(anonymous=True)
    if ldap.ok:
        ldap.users(stop_on_error=False)
        ldap.module("get-desc-users", stop_on_error=False)
        ldap.query(query=["(sAMAccountType=805306368)", "sAMAccountName description"], stop_on_error=False)
        ldap.pass_pol(stop_on_error=False)

    if stored_credential is not None:
        named_ldap = host.ldap(credential=stored_credential)
    else:
        named_ldap = host.ldap()
    if named_ldap.ok and named_ldap.result.data.authenticated:
        named_ldap.bloodhound()

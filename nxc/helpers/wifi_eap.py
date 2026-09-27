"""Preserve EAP lookup/decryption evidence without treating fallback bytes as passwords."""

from dploot.lib.dpapi import decrypt_blob, find_masterkey_for_blob


def recover_eap_credentials(triage, profile, observation):
    observation.update(status="searching", attempts=[], blob=None, credentials=None, error=None)
    try:
        blob = None
        for sid in dict.fromkeys(triage.users.values()):
            for key in triage.eap_profiles_keys:
                path = f"{sid}\\{key}\\{profile}"
                attempt = {"sid": sid, "path": path, "returned_value": False, "error": None}
                observation["attempts"].append(attempt)
                try:
                    candidate = triage.conn.reg_get_key_value("HKU", path, "MSMUserData")
                except Exception as e:
                    attempt["error"] = str(e) or type(e).__name__
                    raise
                if candidate is not None:
                    attempt["returned_value"] = True
                    blob = bytes(candidate)
                    break
            if blob is not None:
                break
        if blob is None:
            observation["status"] = "inconclusive"
            raise RuntimeError("EAP registry lookup returned no value; the adapter cannot distinguish absence from suppressed read errors")
        observation["blob"] = blob
        key = find_masterkey_for_blob(blob, masterkeys=triage.masterkeys)
        if key is None:
            raise RuntimeError("No matching masterkey for EAP profile")
        cleartext = decrypt_blob(blob_bytes=blob, masterkey=key)
        if cleartext is None:
            raise RuntimeError("EAP profile decryption failed")
        prefix = cleartext[168:176]
        # Recognized layouts from the dependency's EAP decoder. Unknown layouts
        # remain errors rather than reporting arbitrary bytes as credentials.
        if prefix not in (b"\x03\x00\x00\x00\x20\x00\x00\x00", b"\x04\x00\x00\x00\x02\x00\x00\x00"):
            raise ValueError("Unsupported EAP credential layout")
        identity = cleartext[176:].split(b"\x00")
        if len(identity) < 2:
            raise ValueError("Truncated EAP identity fields")
        credentials = {"username": identity[0], "domain": identity[1], "password": None}
        observation["credentials"] = credentials
        if prefix == b"\x04\x00\x00\x00\x02\x00\x00\x00":
            index = cleartext.find(b"\x01\x00\x00\x00\xd0\x8c\x9d\xdf\x01", 176)
            if index == -1:
                raise ValueError("Encrypted EAP password blob is missing")
            password_blob = cleartext[index:]
            key = find_masterkey_for_blob(password_blob, masterkeys=triage.masterkeys)
            if key is None:
                raise RuntimeError("No matching masterkey for encrypted EAP password")
            password = decrypt_blob(blob_bytes=password_blob, masterkey=key)
            if password is None:
                raise RuntimeError("EAP password decryption failed")
            credentials["password"] = password.rstrip(b"\x00")
        else:
            password_fields = cleartext[432:].split(b"\x00")
            if len(password_fields) < 2:
                raise ValueError("Truncated EAP password field")
            credentials["password"] = password_fields[1]
        observation["status"] = "recovered"
        return credentials
    except Exception as e:
        if observation["status"] != "inconclusive":
            observation["status"] = "failed"
        observation["error"] = str(e) or type(e).__name__
        raise

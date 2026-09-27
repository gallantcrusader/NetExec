"""Read remote registry values while retaining errors and cleaning up handles."""

from dataclasses import dataclass

from impacket.dcerpc.v5 import rrp
from impacket.examples.secretsdump import RemoteOperations


@dataclass
class RegistryValue:
    present: bool = False
    value: object = None
    registry_type: int | None = None
    error: str | None = None


def read_registry_value(connection, key, name, *, hive="HKLM"):
    open_root = {"HKLM": rrp.hOpenLocalMachine, "HKCU": rrp.hOpenCurrentUser}[hive]
    result = RegistryValue()
    remote_ops = None
    handles = []
    errors = []
    try:
        remote_ops = RemoteOperations(connection.conn, False)
        remote_ops.enableRegistry()
        rpc = remote_ops._RemoteOperations__rrp
        root = open_root(rpc)["phKey"]
        handles.append(root)
        handle = rrp.hBaseRegOpenKey(rpc, root, key)["phkResult"]
        handles.append(handle)
        result.registry_type, result.value = rrp.hBaseRegQueryValue(rpc, handle, name)
        result.present = True
    except rrp.DCERPCSessionError as e:
        if e.get_error_code() != 2:  # ERROR_FILE_NOT_FOUND: missing key or value
            errors.append(str(e))
    except Exception as e:
        errors.append(str(e) or type(e).__name__)
    finally:
        for handle in reversed(handles):
            try:
                rrp.hBaseRegCloseKey(rpc, handle)
            except Exception as e:
                errors.append(f"Closing registry handle: {e}")
        if remote_ops is not None:
            try:
                remote_ops.finish()
            except Exception as e:
                errors.append(f"Finishing registry operation: {e}")
    result.error = "; ".join(errors) if errors else None
    return result


@dataclass
class RegistryWrite:
    requested_value: object
    requested_type: int
    completed: bool = False
    verified: bool = False
    observed: RegistryValue | None = None
    error: str | None = None


def write_registry_value(connection, key, name, value, registry_type):
    """Set an HKLM value and verify it on the same registry connection."""
    result = RegistryWrite(value, registry_type)
    remote_ops = None
    handles = []
    errors = []
    try:
        remote_ops = RemoteOperations(connection.conn, False)
        remote_ops.enableRegistry()
        rpc = remote_ops._RemoteOperations__rrp
        root = rrp.hOpenLocalMachine(rpc)["phKey"]
        handles.append(root)
        handle = rrp.hBaseRegOpenKey(rpc, root, key)["phkResult"]
        handles.append(handle)
        rrp.hBaseRegSetValue(rpc, handle, name, registry_type, value)
        result.completed = True
        result.observed = RegistryValue()
        result.observed.registry_type, result.observed.value = rrp.hBaseRegQueryValue(rpc, handle, name)
        result.observed.present = True
        result.verified = result.observed.registry_type == registry_type and result.observed.value == value
        if not result.verified:
            errors.append("Registry read-back did not match the requested value and type")
    except Exception as e:
        errors.append(str(e) or type(e).__name__)
        if result.observed is not None and not result.observed.present:
            result.observed.error = errors[-1]
    finally:
        for handle in reversed(handles):
            try:
                rrp.hBaseRegCloseKey(rpc, handle)
            except Exception as e:
                errors.append(f"Closing registry handle: {e}")
        if remote_ops is not None:
            try:
                remote_ops.finish()
            except Exception as e:
                errors.append(f"Finishing registry operation: {e}")
    result.error = "; ".join(errors) or None
    return result

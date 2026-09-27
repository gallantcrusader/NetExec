from dataclasses import dataclass, field

from nxc.helpers.misc import CATEGORY
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    """Copy this module to start a custom module with structured results."""

    name = "example_module"
    description = "Example structured module (no remote operation)"
    supported_protocols = ["smb"]  # List the protocols your implementation supports.
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        records: list[dict] = field(default_factory=list)
        reason: str | None = None

    result_type = ResultData

    def options(self, context, module_options):
        """No options available."""
        # Parse options here. For invalid required options, log the reason and
        # call exit(1) imported from sys; the playbook captures that failure.

    def on_login(self, context, connection):
        """Use on_admin_login instead when the operation requires admin rights."""
        # Use the supplied connection. In a playbook, context.session provides
        # its ProtocolSession and context.playbook provides the HostContext.
        # context.credential is the successful login's database reference, when
        # one exists. Reuse it for another protocol via context.playbook.
        # Return observed values in data; logs are for human-readable messages.
        reason = "Example module has no remote operation; replace this hook with your implementation"
        context.log.display(reason)
        return ActionResult(
            connection.args.protocol, self.name, connection.host,
            ResultStatus.SKIPPED, self.ResultData(reason=reason),
        )

        # A real operation should return SUCCESS when its success condition is
        # met, NEGATIVE for a completed negative observation, or FAILED with an
        # error string when it cannot complete. Preserve partial records and
        # add Artifact(path, kind) for output files. Each executed hook must
        # return the declared data type, including early-return/error paths.

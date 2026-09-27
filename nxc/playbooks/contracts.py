"""Validate action-specific results returned by playbook modules."""

from dataclasses import is_dataclass

from nxc.playbooks.results import ActionResult, Artifact, OutputEvent, ResultStatus, json_value


class ResultContractError(TypeError):
    """A module does not satisfy the structured result contract."""


def validate_action_result(result, protocol: str, action: str, target: str) -> ActionResult:
    """Apply the same result envelope contract to protocol actions and modules."""
    label = f"{protocol}.{action}"
    if not isinstance(result, ActionResult):
        raise ResultContractError(f"{label} must return ActionResult")
    if not is_dataclass(result.data) or isinstance(result.data, type):
        raise ResultContractError(f"{label} must return a dataclass instance in data")
    if result.protocol != protocol or result.target != target or result.action != action:
        raise ResultContractError(f"{label} returned a result for a different action or target")
    if not isinstance(result.status, ResultStatus):
        raise ResultContractError(f"{label} returned an invalid status; use ResultStatus")
    if not isinstance(result.inputs, dict):
        raise ResultContractError(f"{label} inputs must be a dictionary")
    if not isinstance(result.events, list) or any(not isinstance(event, OutputEvent) for event in result.events):
        raise ResultContractError(f"{label} events must be a list of OutputEvent objects")
    if not isinstance(result.artifacts, list) or any(not isinstance(artifact, Artifact) for artifact in result.artifacts):
        raise ResultContractError(f"{label} artifacts must be a list of Artifact objects")
    if result.error is not None and not isinstance(result.error, str):
        raise ResultContractError(f"{label} error must be a string or None")
    try:
        json_value(result)
    except (TypeError, RecursionError) as e:
        raise ResultContractError(f"{label} returned data that cannot be saved: {e}") from e
    return result


def validate_module_result(module, result, protocol: str, target: str) -> ActionResult:
    """Require declared, serializable action data from every module hook."""
    result_type = getattr(module, "result_type", None)
    if not isinstance(result_type, type) or not is_dataclass(result_type):
        raise ResultContractError(f"Module {module.name} must declare a dataclass result_type")
    if not isinstance(result, ActionResult):
        raise ResultContractError(f"Module {module.name} must return ActionResult from its hook")
    if not isinstance(result.data, result_type):
        raise ResultContractError(f"Module {module.name} must return {result_type.__name__} in result.data")
    return validate_action_result(result, protocol, module.name, target)

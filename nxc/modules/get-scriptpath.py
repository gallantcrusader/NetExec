import json
from dataclasses import dataclass
from pathlib import Path

from nxc.playbooks.results import ActionResult, Artifact, ResultStatus
from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes


class NXCModule:
    """
    Get the scriptPath attribute of users

    Module by @wyndoo
    """
    name = "get-scriptpath"
    description = "Get the scriptPath attribute of all users."
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        users: list[dict]

    result_type = ResultData

    def options(self, context, module_options):
        """
        FILTER        Apply the FILTER (grep-like) (default: '')
        OUTPUTFILE    Path to a file to save the results (default: None)
        """
        self.filter = ""
        self.outputfile = None

        if "FILTER" in module_options:
            self.filter = module_options["FILTER"]

        if "OUTPUTFILE" in module_options:
            self.outputfile = module_options["OUTPUTFILE"]

    def on_login(self, context, connection):
        # Building the search filter
        resp = connection.search(
            searchFilter="(scriptPath=*)",
            attributes=["sAMAccountName", "scriptPath"]
        )

        context.log.debug(f"Total of records returned {len(resp)}")
        answers = parse_result_attributes(resp)
        context.log.debug(f"Filtering for scriptPath containing: {self.filter}")
        filtered_answers = [answer for answer in answers if self.filter in answer.get("scriptPath", "")]
        errors = [connection.last_search_error] if connection.last_search_error else []
        artifacts = []

        if filtered_answers:
            context.log.success("Found the following attributes: ")
            for answer in filtered_answers:
                context.log.highlight(f"User: {answer['sAMAccountName']:<20} ScriptPath: {answer['scriptPath']}")

            # Save the results to a file
            if self.outputfile:
                error = self.save_to_file(context, filtered_answers)
                if error:
                    errors.append(error)
                else:
                    artifacts.append(Artifact(Path(self.outputfile), "script_paths"))
        else:
            context.log.display("No results found after filtering.")
        return ActionResult(
            "ldap", self.name, connection.host,
            ResultStatus.FAILED if errors else ResultStatus.SUCCESS if filtered_answers else ResultStatus.NEGATIVE,
            self.ResultData(filtered_answers), artifacts=artifacts, error="; ".join(errors) or None,
        )

    def save_to_file(self, context, answers):
        """Save the results to a JSON file."""
        try:
            # Format answers as a list of dictionaries for JSON output
            json_data = [{"sAMAccountName": answer["sAMAccountName"], "scriptPath": answer["scriptPath"]} for answer in answers]

            # Save the JSON data to the specified file
            with open(self.outputfile, "w") as f:
                json.dump(json_data, f, indent=4)
            context.log.success(f"Results successfully saved to {self.outputfile}")

        except Exception as e:
            context.log.fail(f"Failed to save results to file: {e}")
            return str(e) or type(e).__name__
        return None

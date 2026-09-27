from pathlib import Path
from datetime import datetime
from dataclasses import dataclass

from ldap3.utils.conv import escape_filter_chars

from nxc.helpers.path import sanitize_filename
from nxc.parsers.ldap_results import parse_result_attributes
from nxc.playbooks.results import ActionResult, Artifact, ResultStatus
from nxc.helpers.misc import CATEGORY
from nxc.paths import NXC_PATH


class NXCModule:
    """
    Get user descriptions stored in Active Directory.

    Module by Tobias Neitzel (@qtc_de)
    """

    name = "user-desc"
    description = "Get user descriptions stored in Active Directory"
    supported_protocols = ["ldap"]
    category = CATEGORY.CREDENTIAL_DUMPING

    @dataclass
    class ResultData:
        users: list[dict]
        search_filter: str

    result_type = ResultData

    def options(self, context, module_options):
        """
        LDAP_FILTER     Custom LDAP search filter (fully replaces the default search)
        DESC_FILTER     An additional search filter for descriptions (supports wildcard *)
        DESC_INVERT     An additional search filter for descriptions (shows non matching)
        USER_FILTER     An additional search filter for usernames (supports wildcard *)
        USER_INVERT     An additional search filter for usernames (shows non matching)
        KEYWORDS        Use a custom set of keywords (comma separated)
        ADD_KEYWORDS    Add additional keywords to the default set (comma separated)
        """
        self.keywords = {"pass", "creds", "creden", "key", "secret", "default"}

        filters = {name: escape_filter_chars(value).replace(r"\2a", "*") for name, value in module_options.items() if name in ("DESC_FILTER", "DESC_INVERT", "USER_FILTER", "USER_INVERT")}
        if "LDAP_FILTER" in module_options:
            self.search_filter = module_options["LDAP_FILTER"]
        else:
            self.search_filter = "(&(objectclass=user)"

            if "DESC_FILTER" in module_options:
                self.search_filter += f"(description={filters['DESC_FILTER']})"

            if "DESC_INVERT" in module_options:
                self.search_filter += f"(!(description={filters['DESC_INVERT']}))"

            if "USER_FILTER" in module_options:
                self.search_filter += f"(sAMAccountName={filters['USER_FILTER']})"

            if "USER_INVERT" in module_options:
                self.search_filter += f"(!(sAMAccountName={filters['USER_INVERT']}))"

            self.search_filter += ")"

        if "KEYWORDS" in module_options:
            self.keywords = set(module_options["KEYWORDS"].split(","))
        elif "ADD_KEYWORDS" in module_options:
            add_keywords = set(module_options["ADD_KEYWORDS"].split(","))
            self.keywords = self.keywords.union(add_keywords)

    def on_login(self, context, connection):
        context.log.info(f"Starting LDAP search with search filter '{self.search_filter}'")
        response = connection.search(searchFilter=self.search_filter, attributes=["sAMAccountName", "description"])
        errors = [connection.last_search_error] if connection.last_search_error else []
        users = []
        seen = set()
        for item in parse_result_attributes(response):
            username = item.get("sAMAccountName")
            descriptions = item.get("description", [])
            descriptions = descriptions if isinstance(descriptions, list) else [descriptions]
            descriptions = [description for description in descriptions if description]
            if not descriptions:
                continue
            identity = (username, tuple(descriptions))
            if identity in seen:
                continue
            seen.add(identity)
            matches = sorted(keyword for keyword in self.keywords if any(keyword.casefold() in str(description).casefold() for description in descriptions))
            users.append({"username": username, "descriptions": descriptions, "matched_keywords": matches})
            if matches:
                context.log.highlight(f"User: {username} - Description: {descriptions}")
        artifacts = []
        path = Path(NXC_PATH) / f"UserDesc-{sanitize_filename(connection.host)}-{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.log"
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("w", encoding="utf-8") as output:
                print("User:".ljust(25), "Description:", file=output)
                for user in users:
                    for description in user["descriptions"]:
                        print(str(user["username"] or "").ljust(25), description, file=output)
            artifacts.append(Artifact(path, "user_descriptions"))
            context.log.highlight(f"Saved {len(users)} user description records to {path}")
        except Exception as e:
            errors.append(str(e) or type(e).__name__)
            context.log.fail(f"Failed to save user descriptions: {e}")
        return ActionResult(
            "ldap", self.name, connection.host,
            ResultStatus.FAILED if errors else ResultStatus.SUCCESS if users else ResultStatus.NEGATIVE,
            self.ResultData(users, self.search_filter), artifacts=artifacts, error="; ".join(errors) or None,
        )

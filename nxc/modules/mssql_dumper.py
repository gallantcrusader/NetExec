import json
from dataclasses import dataclass, field
from sys import exit
import datetime
import os
from pathlib import Path
import re
from nxc.helpers.misc import CATEGORY
from nxc.helpers.path import sanitize_path_component
from nxc.paths import NXC_PATH
from nxc.playbooks.results import ActionResult, Artifact, ResultStatus, json_value


class NXCModule:
    """MSSQL Dumper v1 - Created by LTJAX"""
    name = "mssql_dumper"
    description = "Search for Sensitive Data across all databases"
    supported_protocols = ["mssql"]
    category = CATEGORY.CREDENTIAL_DUMPING

    @dataclass
    class ResultData:
        matches: list[dict] = field(default_factory=list)
        queries: list[dict] = field(default_factory=list)

    result_type = ResultData

    def options(self, context, module_options):
        """
        SHOW_DATA    Display the actual row data values of the matched columns (default: True)
        REGEX        Semicolon-separated regex(es) to search for in **Cell Values**
        LIKE_SEARCH  Comma-separated list or filename of column names to specifically look for
        USE_PRESET   Use a predefined set of regex patterns for common PII (default: True)
        SAVE         Save the output to a JSON file (default: True)
        """
        self.regex_patterns = []
        self.show_data = str(module_options.get("SHOW_DATA", "true")).lower() in ["true", "1", "yes"]
        regex_input = module_options.get("REGEX", "")
        for pattern in regex_input.split(";"):
            pattern = pattern.strip()
            if pattern:
                try:
                    self.regex_patterns.append(re.compile(pattern))
                except re.error as e:
                    context.log.fail(f"[!] Invalid regex pattern '{pattern}': {e}")
                    exit(1)
        like_input = module_options.get("LIKE_SEARCH", "")
        if os.path.isfile(like_input):
            with open(like_input) as f:
                self.like_search = [line.strip().lower() for line in f if line.strip()]
        else:
            self.like_search = [s.strip().lower() for s in like_input.split(",") if s.strip()]
        self.use_preset = str(module_options.get("USE_PRESET", "true")).lower() in ["true", "1", "yes"]
        self.save = str(module_options.get("SAVE", "true")).lower() in ["true", "1", "yes"]

    def pii(self):
        """Common personally identifiable information (PII) keywords to search for in column names"""
        return ["access_token", "account_number", "address", "allergies", "alt_email", "annual_salary", "apartment",
                "api_key", "auth_code", "auth_token", "bank_account", "bank_code", "bank_id", "bank_name", "bic",
                "billing_address", "birth_date", "blood_type", "card_exp", "card_number", "cardholder_name", "cc_exp_month",
                "cc_exp_year", "cc_number", "ccv", "city", "compensation", "contract_number", "country", "credit_card_expiry",
                "credit_card_hash", "credit_card_number", "credit_card", "creditcard", "cvv", "cvv2", "date_of_birth",
                "debit_card", "diagnosis", "dl_number", "dob", "drivers_license", "ein", "email_address", "email",
                "emergency_contact", "employee_id", "employment_status", "expiration_date", "expiry_date", "fax", "first_name",
                "full_name", "gender", "health_id", "house_number", "iban", "income", "insurance_id", "insurance_number",
                "invoice_id", "invoice_total", "job_title", "last_name", "legal_entity", "legal_name", "location", "login_token",
                "maiden_name", "medical_record", "medication", "mfa_secret", "middle_name", "mobile", "national_id", "nickname",
                "nin", "old_password", "order_amount", "order_id", "order_total", "otp_secret", "passport_number", "passwd_hash",
                "passwd", "password_hash", "password_plaintext", "password_salt", "password", "patient_id", "payment_status",
                "payment_token", "paypal_email", "phone_number", "phone", "phonenumber", "pin_code", "pin", "position",
                "prescriptions", "recovery_key", "refresh_token", "region", "reset_token", "routing_number", "salary", "secret_key",
                "security_answer", "security_code", "security_pin", "security_question", "session_token", "session", "sessionid",
                "social_security_number", "ssn_hash", "ssn", "state", "street", "tax_id", "temp_password", "tin", "token",
                "treatment", "user_credential", "user_name", "user_pass", "user_password", "user_secret", "user_token", "username",
                "zip", "zipcode"]

    def on_login(self, context, connection):
        data = self.ResultData()
        errors, artifacts = [], []
        search_keys = (self.pii() if self.use_preset else []) + self.like_search
        try:
            databases = self.query(connection, data, errors, "SELECT name FROM master.dbo.sysdatabases")
            for database in databases if not errors else []:
                db_name = database["name"]
                if db_name.lower() in ("master", "model", "msdb", "tempdb"):
                    continue
                qualified_db = self.identifier(db_name)
                tables = self.query(connection, data, errors, f"SELECT TABLE_SCHEMA AS table_schema, TABLE_NAME AS table_name FROM {qualified_db}.INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE'")
                for table in tables if not errors else []:
                    schema, name = table["table_schema"], table["table_name"]
                    qualified_table = f"{qualified_db}.{self.identifier(schema)}.{self.identifier(name)}"
                    columns = self.query(connection, data, errors, f"SELECT COLUMN_NAME AS column_name FROM {qualified_db}.INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = {self.literal(schema)} AND TABLE_NAME = {self.literal(name)} ORDER BY ORDINAL_POSITION")
                    if errors:
                        break
                    matched = [column["column_name"] for column in columns if any(key in column["column_name"].lower() for key in search_keys)]
                    if matched:
                        rows = self.query(connection, data, errors, f"SELECT {', '.join(self.identifier(column) for column in matched)} FROM {qualified_table}")
                        for row in rows:
                            data.matches.append({"type": "column_match", "database": db_name, "schema": schema, "table": name, "row": row})
                            if self.show_data:
                                context.log.highlight(f"{qualified_table}: {row}")
                    if errors:
                        break
                    if self.regex_patterns:
                        rows = self.query(connection, data, errors, f"SELECT * FROM {qualified_table}")
                        for row in rows:
                            matched_cells = {}
                            for column, value in row.items():
                                text = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
                                if any(pattern.search(text) for pattern in self.regex_patterns):
                                    matched_cells[column] = value
                            if matched_cells:
                                data.matches.append({"type": "regex_match", "database": db_name, "schema": schema, "table": name, "matched_cells": matched_cells})
                                if self.show_data:
                                    context.log.highlight(f"{qualified_table}: {matched_cells}")
                    if errors:
                        break
                if errors:
                    break
        except Exception as e:
            errors.append(str(e) or type(e).__name__)
        if self.save and data.matches:
            path = Path(NXC_PATH) / "modules" / "mssql-dumper" / sanitize_path_component(f"{connection.host}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.json")
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(json_value(data.matches), indent=2), encoding="utf-8")
                artifacts.append(Artifact(path, "sql_matches"))
                context.log.success(f"Data saved to {path}")
            except Exception as e:
                errors.append(f"Saving SQL matches: {str(e) or type(e).__name__}")
        for error in errors:
            context.log.fail(error)
        return ActionResult("mssql", self.name, connection.host, ResultStatus.FAILED if errors else ResultStatus.SUCCESS if data.matches else ResultStatus.NEGATIVE, data, artifacts=artifacts, error="; ".join(errors) or None)

    def query(self, connection, data, errors, sql):
        step = {"query": sql, "row_count": 0, "error": None}
        data.queries.append(step)
        rows = []
        try:
            rows = connection.conn.sql_query(sql) or []
            step["row_count"] = len(rows)
            if connection.conn.lastError:
                step["error"] = str(connection.conn.lastError)
        except Exception as e:
            step["error"] = str(e) or type(e).__name__
        if step["error"]:
            errors.append(step["error"])
        return rows

    def identifier(self, value):
        return "[" + value.replace("]", "]]") + "]"

    def literal(self, value):
        return "'" + value.replace("'", "''") + "'"

from dataclasses import dataclass, field
from sys import exit

from nxc.helpers.misc import CATEGORY
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    """Observe SQL login/user impersonation and restore the session context."""

    name = "check-impersonation"
    description = "Check SQL login/user impersonation with before/during/after identity observations"
    supported_protocols = ["mssql"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        login: str | None
        user: str | None = None
        database: str | None = None
        initial_database: str | None = None
        observations: list[dict] = field(default_factory=list)
        impersonated: bool = False
        restored: bool = False
        session_discarded: bool = False

    result_type = ResultData

    def options(self, context, module_options):
        """
        LOGIN       SQL login to impersonate for an identity query, then revert.
        USER        Database user to impersonate instead of LOGIN.
        DATABASE    Database for USER (default: current database); restored afterward.
        """
        self.login = module_options.get("LOGIN")
        self.user = module_options.get("USER")
        self.database = module_options.get("DATABASE")
        if bool(self.login) == bool(self.user) or (self.database and not self.user):
            context.log.fail("Specify exactly one of LOGIN or USER; DATABASE requires USER")
            exit(1)

    def on_login(self, context, connection):
        data = self.ResultData(self.login, self.user, self.database)
        errors = []
        try:
            if self.database:
                rows = connection.conn.sql_query("SELECT DB_NAME() AS database_name;") or []
                if connection.conn.lastError:
                    raise RuntimeError(str(connection.conn.lastError))
                if len(rows) != 1 or not isinstance(rows[0].get("database_name"), str):
                    raise ValueError("SQL did not return the original database name")
                data.initial_database = rows[0]["database_name"]
        except Exception as e:
            # No context-changing statement was issued.
            context.log.fail(str(e))
            return ActionResult("mssql", self.name, connection.host, ResultStatus.FAILED, data, error=str(e) or type(e).__name__)
        change_database = "USE [" + self.database.replace("]", "]]") + "];" if self.database else ""
        restore_database = "USE [" + data.initial_database.replace("]", "]]") + "];" if data.initial_database else ""
        # Keep observations in one result set; Impacket exposes the final set.
        # The flag prevents REVERT from popping an existing caller context if
        # EXECUTE AS was denied. There is no persistent database/config change.
        identity = "@@SERVERNAME, ORIGINAL_LOGIN(), SUSER_SNAME(), SUSER_SID(), DB_NAME(), USER_NAME(), IS_SRVROLEMEMBER('sysadmin'), IS_MEMBER('db_owner'), HAS_PERMS_BY_NAME(DB_NAME(), 'DATABASE', 'CONTROL'), HAS_PERMS_BY_NAME(NULL, NULL, 'CONTROL SERVER')"
        query = f"""DECLARE @changed bit = 0, @error_number int = NULL, @error_message nvarchar(4000) = NULL;
DECLARE @observations TABLE (stage int, server_name nvarchar(128), original_login nvarchar(128), effective_login nvarchar(128), login_sid varbinary(85), database_name nvarchar(128), database_user nvarchar(128), is_sysadmin int, is_db_owner int, controls_database int, controls_server int);
INSERT INTO @observations SELECT 0, {identity};
BEGIN TRY
    {change_database}
    EXECUTE AS {"LOGIN" if self.login else "USER"} = N'{(self.login or self.user).replace("'", "''")}';
    SET @changed = 1;
    INSERT INTO @observations SELECT 1, {identity};
END TRY
BEGIN CATCH
    SELECT @error_number = ERROR_NUMBER(), @error_message = ERROR_MESSAGE();
END CATCH;
IF @changed = 1 REVERT;
{restore_database}
INSERT INTO @observations SELECT 2, {identity};
SELECT *, @error_number AS error_number, @error_message AS error_message FROM @observations ORDER BY stage;
"""
        try:
            data.observations = connection.conn.sql_query(query) or []
            if connection.conn.lastError:
                errors.append(str(connection.conn.lastError))
            stages = {row["stage"]: row for row in data.observations}
            if len(stages) != len(data.observations) or not {0, 2}.issubset(stages):
                raise ValueError("SQL did not return distinct before/after identity observations")
            fields = ("server_name", "original_login", "effective_login", "login_sid", "database_name", "database_user", "is_sysadmin", "is_db_owner", "controls_database", "controls_server")
            data.restored = all(stages[0][key] == stages[2][key] for key in fields)
            data.impersonated = 1 in stages
            errors.extend(dict.fromkeys(row["error_message"] for row in data.observations if row.get("error_message")))
            if not data.impersonated and not errors:
                errors.append("SQL did not return an impersonated identity observation")
            if not data.restored:
                errors.append("SQL session identity was not restored")
            for row in data.observations:
                context.log.display(f"Stage {row['stage']}: {row['effective_login']} / {row['database_name']}:{row['database_user']} (sysadmin={row['is_sysadmin']}, db_owner={row['is_db_owner']}, control_db={row['controls_database']}, control_server={row['controls_server']})")
        except Exception as e:
            errors.append(str(e) or type(e).__name__)
        if not data.restored:
            data.session_discarded = True
            connection.playbook_unusable_reason = "SQL impersonation restoration was not verified"
            try:
                connection.close_session()
            except Exception as e:
                errors.append(f"Closing SQL session: {e}")
        for error in errors:
            context.log.fail(error)
        return ActionResult("mssql", self.name, connection.host, ResultStatus.FAILED if errors else ResultStatus.SUCCESS, data, error="; ".join(errors) or None)

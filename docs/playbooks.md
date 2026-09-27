# Python playbooks

The playbook API is under development. Every CLI action and module can return a serializable baseline result. Selected SMB and LDAP actions and the `install_elevated`, `uac`, `runasppl`, `get-info-users`, `groupmembership`, `maq`, `subnets`, `get-desc-users`, `spider_plus`, `spooler`, `webdav`, `enum_ca`, `smbghost`, and `ms17-010` modules provide richer, action-specific data. Other actions and modules use `kind="captured"` with structured log events and their return value; their messages are not yet parsed into action-specific fields.

Install the project's locked dependencies and development tools with `uv sync --frozen --group dev --python 3.13`. The frozen option keeps the existing Git dependency revisions from `uv.lock` without rewriting the lockfile.

Run a Python file that defines `run(host)`:

```shell
nxc playbook examples/playbooks/recon.py targets.txt -u user -p password
```

Use `-d DOMAIN` and `--dns-server ADDRESS` to set connection defaults across a
playbook. The domain applies only to protocols that support domain authentication.
A connection's explicit `domain=` or `dns_server=` overrides the corresponding
default; `local_auth=True` omits the default domain. A stored credential reference
continues to supply its stored domain when reused.

NetExec calls `run(host)` once per target. The host object opens protocol sessions, reuses each protocol and authentication choice for later steps, and closes them at the end of that host's run. This lets an anonymous and a credentialed session remain usable on the same host. An action failure stops only that host by default. Pass `stop_on_error=False` to a connection, action, or module to inspect a failure and continue.

```python
def run(host):
    smb = host.smb(anonymous=True)
    if smb.ok:
        shares = smb.shares()
        if shares.data.shares:
            smb.module("spider_plus", download_flag=True)
```

Every action returns an `ActionResult` with `status`, `kind`, `data`, `inputs`, `artifacts`, `events`, `hook`, and `error`. `kind="typed"` has action-specific data; `kind="captured"` has log events and a return value in `data`. Connection setup, typed actions, and typed modules also retain their log events in `events`. A `NEGATIVE` status represents a condition a playbook can branch on, such as unavailable anonymous access; `FAILED` stops the host unless configured otherwise. For captured results, any `fail`, `error`, `critical`, or `exception` message marks the step failed.

SMB `loggedon_users()` returns deduplicated `data.users` records with `domain`, `username`, and `logon_server`. Pass `loggedon_users="alex.*"` to filter by username. An empty successful enumeration is `NEGATIVE`; an RPC failure is `FAILED`.

LDAP `computers()` returns account names in `data.computers`. LDAP `groups()` returns directory attributes in `data.groups`; `groups(groups="Team")` also returns the resolved `data.members`. Empty results are `NEGATIVE`. A failed search remains `FAILED` even when subsequent member lookups succeed, and any partial records remain available.

LDAP `ous()` returns `data.ous`. With `ous(ous="Team")`, it also returns `data.users` and the selected distinguished name in `data.search_base`. As with the CLI, a named OU search uses the first matching OU as the user-search base. Missing OUs and empty user lists are `NEGATIVE`; search errors are `FAILED`.

Successful and negative connection results expose `connected`, `authenticated`, `anonymous`, `guest`, `signing_required`, and `channel_binding`. SMB connections also expose `admin_privileges`: `true` when NetExec's SCM access check succeeded, `false` on an access denial, and `null` when the check was skipped or inconclusive. `admin_check_error` keeps a transport or RPC error separately. Check `connected` to distinguish an unavailable service from a service that rejected anonymous access. A failed connection can be retried later in the same host playbook.

Use `host.credential("smb", 7)` to refer to credential 7 in the SMB workspace database when opening another protocol:

```python
smb = host.smb()
stored = smb.result.data.credential
if stored is not None:
    ldap = host.ldap(credential=stored)
```

A successful password, NTLM hash, AES key, VNC password, or SSH key login exposes its exact stored row when one exists. You can also use `host.credential("smb", 7)` for a known ID. Ticket cache and certificate logins have no reusable password or key row, so `credential` is `None` for those authentication methods. NFS uses its own host identity rather than a saved login secret.

### Following a path across hosts

Use `host.at(target)` to select another explicitly allowed host. It creates no
network connection until you ask for a protocol. The same target returns the
same host context throughout that root workflow; each target keeps its own
protocol sessions. Credential references work across these contexts:

```python
def run(host):
    ldap = host.ldap()
    if not ldap.ok or ldap.result.data.credential is None:
        return
    sql = host.at("10.60.0.22").mssql(credential=ldap.result.data.credential)
    if sql.ok:
        sql.query(query="SELECT SUSER_SNAME() AS current_login")
```

```shell
nxc playbook path.py 10.60.0.11 --allow-target 10.60.0.22 -u user -p password
```

Positional targets start independent `run(host)` calls. `--allow-target` adds
destinations without starting more workflows; it accepts targets, ranges, or
target files and respects the same exclusions. Every positional target is also
available to `host.at()`. Exact expanded target strings are used for lookups;
an IP and a hostname are not automatically treated as aliases.

All steps append to the root's ordered `HostRun.results`. Its `target` remains
the starting host, while each action retains its actual `target`; the saved run
also lists `allowed_targets`. A failed step on any visited host stops that root
workflow by default, and `stop_on_error=False` still permits branching. Sessions
on all visited hosts are closed when the root finishes or fails. Independent
root workflows have separate sessions and result lists. Custom result writers
receive the same `HostRun` objects, including cross-host steps.

The allow list governs `host.at()` selection. A Python playbook remains trusted
code, and individual operations such as SQL linked-server execution can contact
their own destinations. Declare and check those destinations in the playbook
before issuing such operations.

`examples/playbooks/goad_cross_host_sql.py` follows a stored LDAP credential from
Winterfell to Castelblack and checks the configured Braavos SQL link using SELECT
queries. Its summary retains source/SQL credential references, identity evidence,
and zero-based indices into the root result list. `reached=true` means the observed
SQL sysadmin endpoint was reached; it does not imply Windows or domain control.

`examples/playbooks/goad_laps_path.py` reads Braavos's LAPS value as an Essos
reader, authenticates to Braavos SMB as its local Administrator, then logs in
again through the stored SMB credential reference. It records both admin-check
results, read-only share permissions, the CA publication in AD, and the CA RPC
and web enrollment observations. Run it with Meereen `10.60.0.12` as the starting
target and `--allow-target 10.60.0.23`. For a legacy `ms-MCS-AdmPwd` value,
which supplies no account name, this lab example selects `Administrator`.

The `laps` LDAP module now returns typed per-computer records with the password,
its source attribute, account name when present, DNS name, full LDAP attributes,
and a per-record error if a password payload fails to decode. A Windows LAPS
value is preferred over a legacy value on the same object; a failed encrypted
decode does not silently substitute an older password. An unreadable or absent
password is `negative`, while LDAP and payload errors are `failed`. The result
may retain successful records alongside failures.

Pass protocol connection options as Python keyword arguments. NetExec validates their names against that protocol's CLI arguments and keeps sessions with different options separate:

```python
ldap = host.ldap(anonymous=True, port=636, stop_on_error=False)
if ldap.result.data.connected:
    print(ldap.result.data.channel_binding)
```

`username`, `password`, `hash`, `aesKey`, and `cred_id` may also be supplied for one connection; scalar values are normalized to the lists used by NetExec. Do not combine those authentication options with `anonymous=True` or a `CredentialRef`. Successful logins still use NetExec's credential database, and connection data exposes the resulting `CredentialRef`.

Results are written to JSON under `NXC_PATH/playbooks` by default. Use `--results path.json` to choose another path. Built-in modules still awaiting conversion work through captured results. User-installed modules must declare a dataclass `result_type` on `NXCModule` and return `ActionResult` from each executed hook. These semantic fields support branching; the loader and runner validate declared result types and their JSON serialization.

To save in another format, define `save_results(runs, path)` in the playbook and pass the desired filename with `--results`. Each item in `runs` is a `HostRun` with typed results and a `to_dict()` method:

```python
def save_results(runs, path):
    lines = [f"{run.target},{run.to_dict()['status']}" for run in runs]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
```

Legacy built-in modules also expose `data.records` and `data.fields`. JSON messages keep their JSON value types. Simple `name: value` messages become indexed fields; repeated labels retain every value in order. Plain text and malformed JSON remain text records. The original messages remain available in `events`.

```python
# Inspect a result returned by a legacy built-in module:
if result.kind == "captured":
    counts = result.data.values("User Count")  # "User Count: 2" becomes [2]
    if counts and counts[-1] > 0:
        print(counts[-1])
```

This parser recognizes output syntax; it does not infer what a finding means or whether a check proved absence. Use a module's typed result for those decisions. For text-only output, `data.contains("phrase", level="highlight")` offers a case-insensitive message lookup.

For a user-installed module named `example_custom.py`, the minimal result contract looks like this:

```python
from dataclasses import dataclass

from nxc.helpers.misc import CATEGORY
from nxc.playbooks.results import ActionResult, ResultStatus


class NXCModule:
    name = "example_custom"
    description = "Example structured module"
    supported_protocols = ["smb"]
    category = CATEGORY.ENUMERATION

    @dataclass
    class ResultData:
        count: int

    result_type = ResultData

    def options(self, context, module_options):
        self.count = int(module_options.get("COUNT", "1"))

    def on_login(self, context, connection):
        return ActionResult("smb", self.name, connection.host, ResultStatus.SUCCESS, self.ResultData(self.count))
```

Save it in `NXC_PATH/modules`, then call `smb.module("example_custom", count=3)` from a playbook. Every hook that runs must return the declared result type. A module with both `on_login` and `on_admin_login` returns one result from each hook.

`ldap.module("get-desc-users")` returns `data.users`, a list of `username` and
`description` records. `filter="text"` and `passwordpolicy=True` can be combined;
then both conditions must match. Empty matches are `NEGATIVE`. Search failures
are `FAILED`, with any partial records retained.

`ldap.module("maq")` returns an integer `data.quota`, including zero. An absent
attribute returns `NEGATIVE` with `quota=None`; a search failure returns `FAILED`.

`ldap.module("subnets")` returns `data.sites`. Each site contains `name`,
`distinguished_name`, `description`, `subnets` (directory attribute records), and
`servers` (server names). Set `showservers=False` to omit server queries; the result
records that choice in `data.servers_queried`. Servers are queried once per site,
including sites with no subnets. Search failures retain partial records and mark
the step `FAILED`, even if later searches succeed.

`ldap.module("groupmembership", user="alex")` returns `data.username`,
`data.user_found`, `data.groups` (deduplicated distinguished names),
`data.primary_group_id`, and `data.primary_group`. These are direct memberships
plus the primary group resolved from the user's SID; nested memberships are not
expanded. An unresolved primary group stays `None`, without inventing a DN.
An empty result is `NEGATIVE`; `user_found` distinguishes an existing user with no
returned memberships from a missing user. Failed searches are `FAILED` and retain
any memberships already returned.

Module results identify their origin in `result.hook` (`"on_login"` or
`"on_admin_login"`), including captured results and hook failures. Connection and
protocol-action results have `hook=None`. A module with two executed hooks returns
a list, so branch on `hook` to select the relevant outcome.

UUID values, including LDAP `objectGUID`, stay UUID objects in Python result data
and are saved as canonical strings in JSON. Binary values retain the base64
representation described by their `encoding` and `value` fields. Serialization
reads dataclass fields directly without copying user-provided objects.

LDAP `query()` retains all attribute values in `data.entries` and the corresponding
object DNs in `data.distinguished_names`, in matching order. Referrals are excluded
from these records. Whitespace separates requested attributes; a blank attribute
argument requests all attributes. Empty `query()` and `users()` results are
`NEGATIVE`; search errors remain `FAILED`, including when partial records exist.

LDAP `pso()` returns fine-grained policy attributes in `data.policies` and object-to-policy
links in `data.assignments`. Each assignment has `distinguished_name` and a
`policies` list of policy DNs. Policy attributes retain their LDAP names and raw
values, including time intervals; console formatting does not change the saved
records. Empty enumeration is `NEGATIVE`. Errors from any lookup make the result
`FAILED`, with partial policy and assignment records retained.

LDAP `dc_list()` returns `data.controllers` and `data.trusts`. Controller records
contain `hostname`, `domain`, `record_type`, and `value`; DNS resolution retains
the first successful answer, matching the CLI. Unresolved controllers remain in
the list with `record_type=None` and `value=None`. Trust records preserve LDAP
attributes. LDAP and DNS failures mark the result `FAILED` while keeping collected
records; no controllers or trusts produces `NEGATIVE`. As in the existing CLI,
this action queries DNS for controllers in discovered Active Directory trusts.

LDAP `active_users()` returns enabled-account attributes in `data.users`, with
`data.disabled_count` and `data.unknown_status_count` for excluded records. Missing
account-control attributes do not imply that an account is enabled or disabled.
Raw timestamps and account flags remain in the data. Like `users()`, named-user
filters treat supplied names literally, including LDAP special characters.

`ldap.module("get-info-users", filter="text")` returns `data.users` records with
`username` and `info`. The filter is optional. Empty matches are `NEGATIVE` and
search failures are `FAILED`, retaining partial records.

Action options follow the protocol's CLI argument counts. For example,
`ldap.users(users="alice")` is equivalent to `ldap.users(users=["alice"])`.
Tuples are accepted for multi-value arguments. Fixed-length options such as
`query` require the correct number of values:
`ldap.query(query=("(objectClass=user)", "sAMAccountName description"))`.
Invalid counts produce a failed step before the action executes. Original Python
inputs remain in `result.inputs`, and temporary argument values are restored after
the action.

The CLI exits with code 1 when any host or step fails, including steps run with
`stop_on_error=False`. Continuing controls workflow execution; it does not erase
failures from the final status. Successful runs containing only successful,
negative, or skipped steps exit with code 0. Results stay in target-input order.

`run(host)` and optional `save_results(runs, path)` must be synchronous functions
that accept the indicated positional arguments. Callback signatures are checked
before host execution. Async and generator functions are rejected because this
runner does not await or iterate callbacks.

SMB `uac` and `runasppl` modules return `data.present`, `data.value`, and
`data.enabled`. These describe registry configuration, not proof of runtime
protection. Missing keys or values produce `NEGATIVE` with `enabled=None`.
Access and cleanup failures produce `FAILED`; values already read remain in the
result. Registry handles are closed and RemoteOperations cleanup is attempted
on both success and failure.

SMB `install_elevated` returns `data.machine`, `data.current_user`, and
`data.enabled`. Each registry observation has `present`, `value`, `registry_type`,
and `error`. The current-user lookup is performed only when the machine value is
1; otherwise `current_user=None`. Both observed values must be 1 for `enabled=True`.
Access failures yield `FAILED` with `enabled=None`. The user observation belongs
to the remote registry's current-user context; it is not an enumeration of every
user profile.

LDAP `admin_count()`, `trusted_for_delegation()`, and `password_not_required()`
return `data.accounts` containing the returned LDAP attributes, along with
`data.domain` and `data.search_filter`. Password-not-required records retain
`userAccountControl` so callers can distinguish disabled accounts. Empty matches
are `NEGATIVE`; failed searches are `FAILED` and retain partial records. These
checks report attribute matches, not proof of current privileges or usable access.

FTP `ls(ls="/directory")` returns the requested `data.directory` and raw server
LIST rows in `data.lines`. The previous working directory is restored after a
listing, including on failure. Empty listings are `NEGATIVE`; interrupted listings
are `FAILED` and retain partial rows. LIST formats vary by server, so rows are not
interpreted as portable file metadata.

FTP `cat(cat="/file")` returns `data.path` and exact `data.content` bytes. Binary
and empty files are successful reads. Interrupted transfers are `FAILED` with
partial content retained. JSON exports encode the bytes as base64.

FTP `get(get="/remote/file", get_output="local/path")` downloads a file. Without
`get_output`, the destination is under `NXC_PATH/downloads/ftp/<host>/`.
`put(put=("local/file", "/remote/file"))` uploads a file. Both return
`remote_path`, `local_path`, `bytes_transferred`, and `completed` in `data`.
Completion means the FTP transfer finished successfully; byte counts on failed
uploads describe bytes sent before failure, not confirmed remote persistence.
Downloads attach the created local file as a `download` or `partial_download`
artifact. Transfers execute as actions after login and keep the session open.

SSH `execute(execute="command")` returns `data.command`, exact `data.stdout` and
`data.stderr` bytes, and `data.exit_status`. Streams are drained concurrently.
A nonzero exit status, missing server exit status, transport error, or cleanup
error marks the action `FAILED`. Missing status is represented by `None`.
`no_output=True` suppresses console display; the playbook result still retains
both streams. Command channels are closed while the reusable SSH connection stays
open. Calls from legacy modules supplying an explicit payload retain their
existing string-returning behavior.

SSH `get_file(get_file=("/remote/file", "local/file"))` and
`put_file(put_file=("local/file", "/remote/file"))` accept one pair or a list of
pairs. Results contain `data.transfers`, with `source`, `destination`, `completed`,
and `error` for each attempted transfer. A batch stops at its first failed file;
subsequent pairs are not attempted. Use separate calls with `stop_on_error=False`
to continue after individual failures. Successful downloads attach local artifacts.
SFTP sessions close on success and failure while the shared SSH connection remains
open. Cleanup errors mark the action failed without erasing completed transfers.

MSSQL `query(query="SELECT ...")` returns `data.query`, ordered `data.columns`, and
positional `data.rows`. Positional rows preserve duplicate column names. SQL and
transport errors produce `FAILED` with any returned rows retained. A statement
that successfully returns no rows is `SUCCESS`. A previous SQL error does not
prevent a subsequent playbook query from being attempted.

Decimal values remain `Decimal` objects in Python results and serialize to exact
strings in JSON to avoid loss of precision. Binary values use base64 and SQL NULL
values remain `None`/JSON null.

WinRM `execute(execute="command")` and `ps_execute(ps_execute="command")` return
`command`, the actual `shell`, `stdout`, `stderr`, `exit_status`, `had_errors`, and
`streams`. CMD supplies a numeric exit status; PowerShell supplies an error flag
and named streams instead, so its exit status is `None`. Either reported command
failure or a PowerShell error stream marks the action `FAILED`. Results retain
output even with `no_output=True`. The existing CMD invoke-rights fallback to
PowerShell keeps the action name while recording the actual shell used. Legacy
module calls with explicit payloads retain their existing behavior.

WinRM `get_file(get_file=("C:/remote/file", "local/file"))` and
`put_file(put_file=("local/file", "C:/remote/file"))` return resolved `remote_path`,
`local_path`, and `completed` fields. Downloads attach their successful local
artifact; failed transfers retain paths and the error. Python `Path` inputs are
accepted for local files. `dir(dir="C:/Temp")` returns a command result with raw
directory output and completion status; it does not interpret localized DIR text
as portable file metadata.

WMI `wmi_query(wmi_query="SELECT ...", wmi_namespace="root/cimv2")` returns
`data.query`, `data.namespace`, and `data.records`. Records preserve WMI property
metadata and values. Empty enumeration is `NEGATIVE`; query, enumeration, and
resource-release errors are `FAILED` with partial records retained. The login
interface remains available for later playbook queries and is released when the
session closes. Each query releases its own objects, enumerator, and services.

RDP and VNC `screenshot()` return `data.path`, `data.captured`, and a screenshot
artifact when an image is saved. A capture with no desktop frame is `NEGATIVE`;
capture or file-write failures are `FAILED`. Paths default under
`NXC_PATH/screenshots`. These actions use the protocols' existing screenshot
reconnection behavior rather than an uninterrupted desktop session.

RDP `nla_screenshot()` uses the screenshot result format. If NLA is required, it
returns `SKIPPED`. Otherwise it attempts the existing login-screen capture flow,
retaining capture failures and restoring authentication and negotiation settings
afterward. Captures use timestamp precision to microseconds to reduce filename
collisions across consecutive actions.

NFS `shares()` returns `data.shares` with export `path`, `networks`, `mount_status`,
`uid`, `permissions`, `used_bytes`, `total_bytes`, and per-share `error` fields.
A failed access query leaves its permission unknown (`None`), rather than claiming
denial. Mount status is retained for inaccessible exports. Enumeration errors
produce `FAILED` with partial records retained. The original authentication values
and NFS client are restored after enumeration.

NFS `enum_shares(enum_shares=3)` returns `data.shares` with each export's path,
networks, mount status, directory `entries`, and error. Omitting the depth uses 3.
Entries retain the existing path, UID, permission, and display-size fields.
Partial listing and access-check errors mark the action `FAILED` while preserving
collected entries. Mounted exports are unmounted and session state is restored.

Typed protocol and module results share validation rules: `status` must be a
`ResultStatus`, `data` must be a dataclass instance, `inputs` a dictionary,
`events` a list of `OutputEvent` objects, and `artifacts` a list of `Artifact`
objects. Invalid or unserializable results become failed steps and follow the
usual stop/continue behavior.

### SMB terminal sessions

`session.qwinsta()` returns `TerminalSessionsData.sessions`: records with an `id`
plus the terminal service fields (`Username`, `Domain`, `SessionName`, `state`,
`RemoteIp`, and available session flags and timestamps). Filter with
`session.qwinsta(qwinsta="alice")` or a username file path. A completed lookup
without matching sessions is negative. Detail or address retrieval errors fail
the action while retaining the available session records; absent details should
not be interpreted as evidence of an inactive session. Timestamps serialize as
ISO strings. Enumeration handles are closed even when the RPC lookup fails.

### SMB disks and local groups

`session.disks()` returns `SMBDisksData.disks` with disk names such as `C:`.
`session.local_groups()` returns `LocalGroupsData` containing group name/RID and
member SID/name mappings. Use
`session.local_groups(local_groups="Administrators")` to query members;
`members_queried` distinguishes that request from a group-only inventory.
A found group with no members is still a successful lookup. No matching groups
or disks is negative. RPC, member lookup, database-write, and cleanup errors
fail the action, retaining any records already available. Both actions release
their RPC connections without closing the shared SMB session.

### SMB file transfers

`session.get_file(get_file=[remote_path, local_path])` and
`session.put_file(put_file=[local_path, remote_path])` return `SMBTransfersData`.
Pass a list of pairs for multiple files. Each record includes the share, remote
and local paths, bytes transferred through the file callback, completion flag,
and error. The batch stops at the first failed file. For failed uploads, the
byte count describes bytes supplied to SMB, not confirmed remote persistence.
Downloads expose artifacts, including `partial_download` artifacts after a
failure. Empty files are successful transfers. A sharing-violation retry clears
partial local contents before restarting. `append_host=True` prefixes the
explicit destination filename while preserving its parent directory.

### SMB directory records

`session.dir(dir="Folder", share="DATA")` returns `SMBDirectoryData` with the
share, requested path, and `entries`. Each entry has `name`, `path`,
`is_directory`, `readonly`, `size` (bytes), and `modified_epoch` (Unix seconds).
The read-only flag is a file attribute, not an effective-access check. Entries
such as `.` and `..` are preserved if returned by the server. Empty listings
are negative; listing or metadata failures retain preceding entries and fail
the action.

For example, after connecting an SMB session:

```python
listing = session.dir(dir="Reports", share="DATA")
for entry in listing.data.entries:
    if not entry.is_directory and entry.name.endswith(".csv"):
        print(entry.path, entry.size)
```

### Computer inventory module

`session.module("dump-computers")` returns computer records with
`dns_hostname`, `dns_short_name` (the first DNS label), and `operating_system`.
A missing OS remains `None` in structured data. The module's existing TYPE
option controls `output_lines` and console/file presentation; it does not
remove fields from the records. Computers without DNS hostnames remain omitted,
matching the module's existing behavior. OUTPUT produces a `computer_list`
artifact after a successful write. Search or file-write failures retain the
collected records and fail the action.

### Computer search module

`session.module("find-computer", TEXT="SQL")` returns the search text and
computer records containing `dns_hostname`, `operating_system`, `address`, and
`resolution_error`. TEXT is a literal substring, including LDAP-special
characters. Missing OS values remain `None`; DNS hostnames are required for
inclusion. The address is the one selected by NetExec's configured resolver,
which can be IPv4 or IPv6. LDAP and DNS failures fail the action while retaining
records already found. No matching computers is negative. To inspect results
when resolution fails, use the module call's `stop_on_error=False` option.

### SQL linked-server records

`session.module("enum_links")` returns `servers`, `login_mappings`, and
`login_mappings_queried`. Records retain the column names and values returned
by `sp_linkedservers` and `sp_helplinkedsrvlogin`, including mappings whose
`Local Login` or `Remote Login` is null. Login mappings are queried only for
sessions with administrator privileges, matching existing module behavior.
An unqueried mapping list does not establish that no mappings exist. Query
errors fail the action and preserve available server or mapping records.
No servers or mappings found is negative.

### SQL login records

`session.module("enum_logins")` returns `default_domain` and `logins` with
`name`, `type`, `type_desc`, `is_disabled`, `create_date`, and a derived
`login_type`. Creation dates serialize as ISO strings. A Windows login with
the default-domain prefix is labeled `Domain User`; other Windows logins are
labeled `Windows User` because a different prefix does not prove local-machine
membership. Missing disabled status is displayed as unknown. Domain lookup
failures do not discard subsequent login records, but still fail the action.
The existing exclusions for `##` principals and principal-type filter remain.

### SQL impersonation permission records

`session.module("enum_impersonate")` returns `permissions`, preserving each
visible server permission's grantee, grantor, target login, principal IDs,
permission name, class, and grant/deny state. A null `target_login` can describe
a server-wide permission or a principal name that is not visible. These are
catalog permission records, not a calculation of effective impersonation rights
through roles, ownership, or other permissions. A successful result means
records were found, including DENY records. Query failures fail the action;
no visible records is negative. The module performs enumeration only.

### LDAP user attributes

`get-scriptpath`, `get-userPassword`, and `get-unixUserPassword` return `users`
containing the original LDAP attribute names and parsed values. Multiple
attribute values remain lists; missing values are not invented. Password
attribute observations are not authenticated credentials and do not establish
that the values can be used to log in. All three modules report LDAP search
errors as failed results while retaining available records. Empty matches are
negative. `get-scriptpath` preserves FILTER behavior and exposes successful
OUTPUTFILE exports as `script_paths` artifacts; write failures fail the action.

### Registry network interfaces

`session.module("enum_interfaces")` returns `interfaces` with an adapter `id`,
`name`, and `values` for static and DHCP address, subnet, gateway, and DHCP-enable
settings. Each name/value is a `RegistryValue` with `present`, `value`,
`registry_type`, and `error`. Raw multi-string values retain their null
separators. Missing values are distinct from denied or failed reads. Registry
settings describe configured IPv4 interfaces, not verified live connectivity.
Records are retained on partial failures; handle or RemoteOperations cleanup
failures also fail the action. Adapter names use `CurrentControlSet`.

### Host and account identity

`hyperv-host` returns a normalized `hostname` plus the original `RegistryValue`.
A missing guest registry value is negative, not evidence that virtualization is
absent. Read and cleanup failures are failed results, retaining any observed
value. `whoami` returns the selected `username` and parsed LDAP `users` records,
including multivalued memberships and raw account-control fields. USER is an
exact account-name lookup; it defaults to the session username. Search errors
retain available records. These records describe directory attributes, not a
complete calculation of effective privileges.

### Registry value operations

`reg-query` returns the selected `operation`, `path`, `key`, an `observed`
RegistryValue, requested value/type, and `completed`. The observation describes
the value read before a set/delete operation. A completed set/delete means the
RPC call returned successfully, not that a separate read-back verified it.
Cleanup failures fail the action while preserving its completion flag, allowing
playbooks to avoid blindly retrying a completed write. Missing query/delete
values are negative. Setting creates a missing value in an existing key, not
a missing key hierarchy. DELETE and VALUE are mutually exclusive; an empty KEY
selects the default value. HKLM/HKCU/HKCR and their long names are supported.

### Remote UAC setting changes

`remote-uac` returns the requested `action` and a registry write record with
`requested_value`, `requested_type`, `completed`, `verified`, `observed`, and
`error`. Enable requests LocalAccountTokenFilterPolicy=0; disable requests 1.
The value and type are read back on the same registry connection. Read-back or
cleanup failures retain the completed flag so a playbook can distinguish a
failed write from a completed write followed by an error. Verification confirms
the stored setting, not the privilege level of an existing or future session.

### Legacy OS inventory

`obsolete` returns `computers` and the exact `search_filter` used. Records keep
LDAP attributes plus `address`, `pwdLastSet_readable`, and `resolution_error`.
Missing password timestamps remain unknown; zero is displayed as never set.
The module retains its existing OS-name filter; a match is not an independently
verified assessment of current vendor support. LDAP, DNS, and export failures
fail the action while retaining records. Successful exports are `obsolete_hosts`
artifacts under `NXC_PATH/logs`, named by domain, target, and timestamp to avoid
hosts overwriting each other's output. DNS uses NetExec's configured resolver.

### Remote connectivity checks

`test_connection` returns `destination`, `reachable`, and the command `output`.
A Boolean True result succeeds; False is negative. Execution errors, absent
output, or non-Boolean output fail the action with `reachable=None`. The check
runs from the connected SMB/MSSQL host to the HOST option, not from the machine
running NetExec. A negative ping result alone does not establish that other
protocols are unreachable. The destination is passed as a literal PowerShell
argument. No connectivity checks were run against live hosts during development.

### MSSQL channel-binding check

`mssql_cbt` returns `tls_required`, `attempted`,
`authenticated_without_cbt`, `cbt_required`, and `reason`. Successful
empty-CBT authentication sets `cbt_required=False` for that tested connection.
Rejected authentication is an inconclusive failed result with
`cbt_required=None`; it does not prove enforcement. Local SQL authentication,
unknown TLS requirements, and servers that do not require TLS skip the probe.
The check uses a temporary connection, closed even on failure, while retaining
the original SQL session. Cleanup failures preserve authentication observations.

### NTLM setting and accessibility-binary checks

`ntlmv1` returns the observed LmCompatibilityLevel as `registry`. Any present
value is a successful observation; absence is negative and a failed read is
failed. It does not attempt NTLMv1 authentication or infer effective policy
from a missing value.

`lockscreendoors` returns per-file descriptions, expected descriptions,
`matches_expected`, `matches_shell_description`, and errors. Unknown comparisons
remain `None`. Mismatches are findings (success), complete matching checks are
negative, and unreadable/unparseable files fail the action while preserving
other findings. Description comparisons are heuristic; a match does not prove
file integrity and a mismatch does not prove a backdoor.

### OXID address bindings

`ioxidresolver` returns normalized, deduplicated `addresses` plus all returned
`bindings` with network address, tower ID, and parsed IP address (or `None` for
non-IP bindings). DIFFERENT filters the address list using normalized IPs,
including equivalent IPv6 spellings; raw bindings remain available. Reported
bindings are observations, not proof that every address is reachable. Query or
cleanup errors fail the action and retain available records. The temporary RPC
connection is closed independently of the shared protocol session.

### SMB-backed WMI queries

`session.wmi_query(wmi_query="SELECT Name FROM Win32_ComputerSystem")` on SMB
returns query text, namespace, and WMI property records. Partial enumeration
and cleanup failures retain records. Explicit internal callers of
`connection.wmi_query(wql)` still receive lists, with errors available through
`connection.last_wmi_error`. Query objects and owned WMI/DCOM resources are
released; the shared SMB connection remains open. Callback callers retain their
existing record-collection API and ownership of objects they retrieve.

### WMI network adapter configuration

`get_netconnections` returns `adapters` containing WMI property records for
IP addresses and DNS suffix search order. Null and multivalued properties remain
intact. The saved raw JSON log is exposed as a `network_connections` artifact
under `NXC_PATH/logs`; target and microsecond timestamp distinguish each export.
Partial query or file-write errors fail the action while preserving records.
Explicit WMI queries made by modules during a playbook retain the shared login,
release their query resources, and expose errors through `last_wmi_error`.

### Snapshot inventories

SMB `list_snapshots(list_snapshots="DATA")` returns the selected `share` and
snapshot path strings, closing its temporary tree connection while preserving
the SMB session. Cleanup errors retain discovered snapshots and fail the action.
WMI `list_snapshots()` returns WMI query data, including each snapshot's
`VolumeName`. It enumerates all volumes; its legacy optional share argument is
retained in inputs but does not filter that query. WMI results preserve partial
records and query-resource cleanup errors.

Callback-based WMI queries in playbooks use the same owned-resource cleanup as
ordinary queries. Their collected records survive callback and cleanup errors,
available through `last_wmi_error`; normal `S_FALSE` enumeration completion is
not an error. The callback continues to own the individual WMI objects it
retrieves, while the query runner owns the enumerator and services interfaces.

### KeePass discovery

`keepass_discover` returns `processes`, `files`, `processes_queried`,
`files_queried`, and raw command `outputs`. Process records preserve ID, user,
and process name. File discovery returns paths. SEARCH_TYPE selects the checks;
unqueried lists do not mean no findings exist. The PowerShell searches produce
JSON records with errors, allowing partial findings to survive access failures.
Malformed or absent output fails the action. As before, SEARCH_PATH is a
PowerShell path expression; the defaults now expand the Program Files variables.

### SMB process inventory

`session.tasklist()` returns `processes` with `image_name`, `pid`, `session_id`,
`sid`, and `working_set_bytes`. Use `tasklist="name"` for a case-insensitive
substring filter. An empty match is negative. Enumeration, server-handle close,
and RPC-context cleanup failures fail the action while preserving records.
The terminal server handle is closed, and the shared SMB session remains open.

### User-description searches

`user-desc` returns `users` with username, all nonempty description values, and
matched keywords, plus the applied `search_filter`. Identical account/description
records are deduplicated. Keyword matching remains case-insensitive and controls
highlighting rather than removing other descriptions from results. Standard
filters retain wildcard support and escape other LDAP-special characters;
LDAP_FILTER remains an explicit full filter. Saved logs are `user_descriptions`
artifacts under `NXC_PATH`. Search and file-write errors retain collected records.

### Group membership changes

`modify-group` returns user, group, removal flag, resolved LDAP DNs or SAMR RIDs,
and `completed`. Completion records the server's successful modification
acknowledgment; it does not imply a separate membership read-back. LDAP lookups
use exact escaped account names and require one unambiguous result. Lookup or
modification errors fail the action. SAMR cleanup errors preserve completion,
so a playbook can avoid blindly repeating an acknowledged change. Existing SAMR
global-group and same-domain limitations remain. Development tests use mocked
LDAP/SAMR calls only.

### Policy privilege assignments

`gpp_privileges` returns `policies` with file paths, privilege names, principal
SID/name pairs, and per-file errors. Unresolved names remain `None`; SIDs remain
available. The parser preserves empty assignments and ignores unrelated INF
sections. NO_LDAP controls optional resolution; one temporary LDAP connection is
reused across the files and closed afterward. File-read, decode, connection, and
cleanup errors retain collected policy records. These are policy-file
assignments, not a calculation of effective rights on the connected host.

### Shared sessions inside modules

During a playbook module hook, `context.session` is the calling protocol session,
`context.playbook` is its host context, and `context.credential` is the stored
credential reference (or `None` when unavailable). Modules can reuse the normal
host connection cache and database credential resolution:

```python
if context.credential is not None:
    ldap_session = context.playbook.ldap(credential=context.credential)
    users = ldap_session.users()
```

These fields are provided for playbook hooks, not ordinary CLI module execution.
An absent reference does not imply anonymous access; the module must choose its
authentication behavior explicitly. Modules must leave host-owned sessions open;
the playbook closes them at the end of the host run.

In playbooks, `gpp_privileges` now uses the host's cached LDAP session and the
calling module's database credential reference. An explicitly anonymous source
session can request anonymous LDAP. If neither is available, the module retains
policy records and reports that resolution could not be authenticated. It does
not close the host-owned LDAP session. SID queries become ordinary recorded
playbook actions, including partial-query failures. Well-known SIDs require no
LDAP connection; ordinary CLI runs retain the temporary-connection behavior.

### DNS enumeration

`session.module("enum_dns")` returns `data.zones`, `data.queried_zones`, and
`data.records`. Each record contains its `zone`, exact `text` representation,
and complete WMI `properties` dictionary, including the provider's values and
metadata. `DOMAIN` limits enumeration to one zone. For example:

```python
result = smb.module("enum_dns", DOMAIN="example.test")
for record in result.data.records:
    print(record["zone"], record["text"])
```

The module works through SMB or WMI and preserves raw DNS text instead of
splitting it on spaces, which would lose information in TXT records. A failed
query retains partial results and stops further zone queries. An empty,
successful query is negative. The text export is listed as a `dns_records`
artifact under `NXC_PATH/logs`; export failures retain records and report failure.
These behaviors have offline mock coverage; live DNS enumeration has not been
verified in this workspace.

### ADCS enrollment inventory

`ldap.module("adcs")` returns `data.services` and a deduplicated
`data.templates` list. Each service contains its LDAP `attributes`, extracted
web-service `urls`, and `templates`. A service with no published templates is
still a discovered service. `SERVER` selects an enrollment service by its
literal CN; `BASE_DN` overrides the domain DN used below `CN=Configuration`.
Queries reuse the active LDAP connection. Partial records survive a query
failure; an unsuccessful search is distinct from a successful empty search.

### Retired module entry points

Retired modules return a failed result with `data.replacement` identifying the
supported entry point (`module:NAME`, `action:NAME`, or `connection:ldap` for
LDAP banner checks). They follow the usual stop-on-error setting. This applies
to `dfscoerce`, `petitpotam`, `printerbug`, `shadowcoerce`, `efsr_spray`,
`firefox`, `ntlm_reflection`, `group-mem`, `pso`, `enum_trusts`, and
`ldap-checker`. A replacement identifier is informational; choosing it remains
an explicit step in the playbook.

### LDAP DNS inventory

`ldap.module("get-network")` returns `data.zone`, `data.search_base`, the LDAP
`data.nodes`, all `data.records`, and the selected `data.export_lines`. Records
retain the owner name and FQDN, numeric and named type, TTL, serial, timestamp,
rank, flags, tombstone state, and original binary record. A/AAAA addresses and
NS/CNAME/PTR names also have a decoded `value`; other types retain their raw
bytes and numeric type without an inferred value.

The inventory preserves duplicate addresses and their distinct owner names.
The default text export contains unique IP addresses. `ALL=True` exports owner
names with address/name values, and `ONLY_HOSTS=True` exports owner names.
Tombstoned records remain in the inventory and are omitted from the export.
The zone apex (`@`) exports as the zone itself. Artifacts use `NXC_PATH/logs`
and have kind `dns_inventory`. Query and export errors retain collected data
and produce failed results. Enumeration continues to use the domain's zone
under `DomainDnsZones`; it does not enumerate every DNS partition or zone.

### OS patch comparisons

`smb.module("enum_cve", CVE="CVE-2025-33073")` returns `data.os_version`,
`data.ubr`, and `data.checks`. Each check identifies the CVE and alias, its
stored minimum patched UBR, a nullable `below_patch_threshold`, applicability
observations, and a status/reason. UBR zero is a valid revision.

An unknown OS build or an undetermined required domain-controller role is a
failed, inconclusive result. A DC-only check on a known non-DC is skipped.
Known comparisons below the threshold produce success; comparisons at or above
it produce negative. RPC and cleanup failures retain any observations already
collected. These are comparisons against the module's existing patch table,
not verification of vulnerable components, mitigations, or exploitability;
this integration does not update or independently validate that table.

### Winlogon registry inventory

`smb.module("reg-winlogon")` returns `data.values`, keyed by registry value
name, and `data.queried_names`. Each value records `present`, the raw `value`,
its `registry_type`, and any per-value `error`. Raw strings retain their
terminating nulls. Missing values are distinguished from access failures;
a failure stops further reads while preserving earlier observations. The
module uses one registry RPC session over the existing SMB connection and
reports cleanup failures. These stored values are not authenticated
credential references.

### WDigest registry operations

`smb.module("wdigest", ACTION="check")` returns the raw `data.observed`
registry value and a nullable `data.enabled`. Missing values are reported as
absent; unexpected types or values fail instead of being interpreted as a
known setting. `ACTION="enable"` sets DWORD 1, while `ACTION="disable"`
deletes the value, preserving the existing module's behavior.

For changes, `data.completed` records acknowledgment of the write/delete and
`data.verified` records matching read-back. Disabling an already absent value
can be verified without a completed delete. Access failures are distinct from
absence, and cleanup errors retain the observations and completion flags.
These results describe the registry setting, not effective credential storage
behavior for a particular Windows version or existing logon session.

### Linked-server command results

`mssql.module("exec_on_link", LINKED_SERVER="name", COMMAND="SELECT 1")`
and `mssql.module("link_xpcmd", LINKED_SERVER="name", CMD="whoami")`
return the selected `linked_server`, original `command`, generated `query`, raw
`rows`, and a `completed` flag in `data`. `link_xpcmd` additionally returns the
`output` values without trimming whitespace or dropping null/empty rows.
Server identifiers and nested SQL string literals are quoted independently.

`completed` means the SQL batch returned without a reported SQL error; it does
not assert the exit status of an operating-system command. A completed batch
with no rows is successful. SQL errors produce failed results and retain
returned rows. Both modules reuse the caller's SQL connection and leave it open.

### SQL configuration changes

`mssql.module("enable_cmdshell", ACTION="enable")` and
`mssql.module("link_enable_cmdshell", LINKED_SERVER="name", ACTION="disable")`
return the original `before` settings, latest `observed` settings, and a
`queries` trail containing SQL, returned rows, and errors. `completed` means
the requested configuration batch was acknowledged; `verified` means both
configured and running xp_cmdshell values matched the request on read-back.

When `show advanced options` must be temporarily enabled,
`restoration_required` is true and `restored` records the result of restoring
and reading back its original state. Restoration is attempted even after a
failed query that may have applied a change. Restoration errors fail the step
without discarding completed-change observations. A pre-existing pending
change to `show advanced options` stops the operation before writes because
applying `RECONFIGURE` would prevent preserving that state. Both modules use
the existing SQL connection; the linked variant runs its queries on the named
linked server.

### PowerShell history files

`smb.module("powershell_history", EXPORT=True)` returns `data.files` with the
user, remote path, original `content` bytes, decoded `text`, matched `keywords`,
read `complete` flag, and per-file `error`. `data.queried_users` identifies the
profiles whose PSReadLine folders were queried. Keyword matches are simple
substring matches; they are not verified credentials.

Missing history folders are normal empty results. Access failures stop the
module and retain earlier files; interrupted downloads retain partial bytes
with `complete=False`. Text decoding replaces invalid UTF-8 for display while
original bytes remain available. `EXPORT=False` disables export. When enabled,
each file gets a separate `powershell_history` artifact under
`NXC_PATH/modules/powershell_history`, preserving its exact bytes. An export
failure retains the downloaded file in the result and fails the step.

### Recent-file shortcuts

`smb.module("recent_files")` returns `data.shortcuts`, a unique `data.paths`
list, and `data.queried_users`. Each shortcut retains its user, source path,
original bytes, `downloaded` and `parsed` flags, parsed `target`, and error.
Duplicate targets remain as separate shortcut records so their user/source
relationships are preserved. Target strings are not stripped or rewritten.
A valid shortcut without a filesystem target has `target=None`.

Missing Recent folders are normal empty results. Access, download, and parsing
errors stop the module with a failed result while preserving earlier records
and any partial download. A shortcut target is historical metadata; this
module does not verify that the referenced file still exists.

### BitLocker inventory

`smb.module("bitlocker")` and `wmi.module("bitlocker")` return a common
`data.volumes` list with mount point, numeric protection status, numeric
encryption method, and nullable `protection_enabled`. Status 0 maps to false,
1 to true, and other/missing statuses remain unknown. Protection state does
not by itself indicate whether a volume is fully encrypted.

`data.records` retains provider records; the SMB path also retains its raw
PowerShell JSON `output`. Unknown encryption methods remain as numeric values.
WMI uses packet privacy and retains the playbook's shared login while releasing
query resources. Missing namespaces/cmdlets and query errors produce failed
results; a successful empty query is negative. These integrations have offline
coverage; no live BitLocker inventory was performed.

### rclone configuration inventory

`smb.module("rclone")` returns `data.files` and `data.queried_users`. Each file
contains its user, remote path, original bytes, read `complete` flag,
`encrypted` flag, parsed `entries`, and error. Entries retain their section,
name, stored value, and decoded `plaintext` for supported obscured password
fields. Duplicate names in different sections remain distinct.

Missing files produce no file record. Access failures and interrupted reads
produce failed results with available bytes and earlier entries preserved.
Malformed configuration or password decoding stops the module and records the
error. Entirely encrypted configurations are retained without decoding; when
all found files are encrypted, the result is skipped. Decoded secrets have not
been authenticated and are not credential references.

### AWS credential-file discovery

`session.module("aws-credentials")` returns `data.paths`, the configured
`data.search_path`, and its `source`. SMB and WinRM retain the raw PowerShell
JSON `output`; reported search errors fail the result without dropping found
paths. A completed search with no matches is negative.

SSH walks shell-quoted literal `SEARCH_PATH_LINUX` roots through an SFTP
channel on the existing SSH connection. It does not require remote `find` or
`grep`, does not follow symlinks, and reports access/cleanup failures. Files
named `credentials` containing `aws_` match on SSH; Windows preserves the
existing case-insensitive `aws` content search. These paths are candidate files,
not authenticated credentials. SSH servers must support SFTP for this module.

### Notepad++ backups

`smb.module("notepad++")` returns `data.files` and `data.queried_users`.
Files retain their user, remote path, original `content` bytes, display `text`,
read `complete` flag, and error. Text is no longer lowercased. Invalid UTF-8 is
replaced only in the display text; saved files preserve the original bytes.

Each completed download is saved as a separate `notepad_backup` artifact under
`NXC_PATH/modules/notepad++`. Missing backup folders are normal empty results.
Access, read, and export failures stop the module while preserving earlier
records and artifacts. Interrupted reads retain partial bytes without marking
them complete or exporting them as completed backups.

### Wi-Fi profiles

`session.module("wifi")` supports SMB, WMI, WinRM, and MSSQL using the
connection's existing DPAPI adapter. `data.profiles` retains interface and
source path, raw XML, SSID, authentication and encryption settings, recovered
passwords/EAP fields, and per-profile errors. `data.masterkey_count` reports
available system masterkeys. Open profiles can be inventoried with no keys.

`data.enumeration_complete` describes profile-file enumeration and processing.
Missing/unreadable listings, malformed XML, missing PSK masterkeys, and failed
PSK decryption fail the step while retaining profiles already encountered.
EAP lookup retains an `eap_observation` with registry attempts, the original
DPAPI blob, recovered identity fields, status, and error. User masterkeys are
collected once when an enterprise profile is encountered. Known supported
EAP layouts are decoded explicitly; missing keys, unsupported layouts, and
failed nested-password decryption fail the step and retain partial identity
fields with `password=None`. Undecrypted fallback bytes are not returned as a
password. If a registry adapter returns no value, the result is failed and
`inconclusive`, since the adapter can suppress read errors. This does not prove
that the registry value is absent. `eap_lookup_status` is `not_requested`,
`recovered`, `failed`, or `inconclusive`.
Recovered values have not been authenticated and are not credential references.

### Entra ID sync-server candidates

`ldap.module("entra-id")` returns raw `data.msol_accounts`,
`data.adsync_accounts`, and `data.candidates`. Each candidate retains its
source (`msol_description` or `adsync_backlink`), source account and evidence,
computer lookup records, hostname, resolver result, and resolution error.
Multiple backlinks and overlapping candidates remain separate so account
relationships are not lost. Unresolved backlinks retain their DN evidence.

LDAP or resolver failures stop further lookups and retain earlier results.
A candidate is inferred from directory attributes; it does not prove a sync
service is installed or running on that host.

### Security-question inventory

`smb.module("security-questions")` returns `data.domains` and `data.users`.
User records retain domain name/SID, username/RID, raw reset data, parsed
`reset_data`, question/answer records, status, and error. Domain and user lists
are paginated; the built-in alias domain is excluded from user queries.

Empty reset data is a queried user with no questions. Unsupported information
classes are recorded per user; an entirely unsupported result is skipped.
Access, parsing, pagination, or cleanup failures fail the step and retain
collected records. All opened handles and the temporary SAMR connection have
cleanup paths. The shared SMB connection is retained.

### Onelogon configuration observations

`smb.module("onelogon")` returns typed results for its login and administrator
hooks. The SYSVOL result has `data.source="sysvol"` and `data.policies`,
including policy name/path, original bytes, read-completion state, matching
configuration entries, and errors. Matches retain section, key, original
value, and parsed CSV fields. Missing security templates are normal; access,
read, or parsing errors fail the step with partial records preserved.

The administrator hook has `data.source="registry"` and a registry observation
with presence, raw value/type, and error. Registry cleanup failures retain the
observed value. These are configuration observations; finding an allow-list
does not establish that a particular account is exploitable.

### SQL data search

`mssql.module("mssql_dumper", LIKE_SEARCH="password", SAVE=True)` returns
`data.matches` and a `data.queries` trail. Matches retain database, schema,
table, match type, and original row/cell values. Regex matching uses a textual
view of each value without stripping it; matched results retain the original
value. Column-name searches and preset behavior remain available.

All table references are fully qualified and quoted. The module does not
change the shared connection's current database. Query failures stop further
scanning, preserve matched partial rows, and record the failed query and row
count. `SAVE=True` exports matches as a `sql_matches` JSON artifact using the
shared serializer, including binary values. Invalid regex options stop the
module instead of silently dropping the pattern. Matches are search results,
not a determination that their contents are credentials or sensitive data.

### SQL login and database-user impersonation observations

`sql.module("check-impersonation", login="sa")` runs an identity query before,
during, and after a temporary SQL LOGIN impersonation. It returns typed
`observations`, `impersonated`, `restored`, and `session_discarded` fields.
Each observation includes the effective login/SID, original login, database,
database user, and SQL sysadmin membership. No arbitrary command or configuration
change is part of this check. SQL errors remain failed results even when the
original identity was restored.

Use `sql.module("check-impersonation", user="dbo", database="msdb")` for a
database USER instead of a LOGIN. `database` is optional for USER and defaults
to the current database; an explicitly selected database is restored afterward.
LOGIN and USER are mutually exclusive. Observations also retain `is_db_owner`,
`controls_database`, and `controls_server`, including SQL NULL values. The
effective permission checks use SQL Server's
[HAS_PERMS_BY_NAME](https://learn.microsoft.com/en-us/sql/t-sql/functions/has-perms-by-name-transact-sql).
Database ownership does not automatically mean server or Windows control.

Restoration follows SQL Server's [REVERT semantics](https://learn.microsoft.com/en-us/sql/t-sql/statements/revert-transact-sql).
The batch only reverts when its own EXECUTE AS succeeded. If before/after identity
cannot be verified, the connection is closed and marked unusable. Further calls
on that session fail; asking the host for the same connection again creates a
replacement. `goad_sql_impersonation.py` also checks a follow-up query and session
reuse on the three configured LOGIN routes.

### Structured DACL evidence

`ldap.module("daclread", target="jaime.lannister", principal="tywin.lannister")`
returns `data.objects`, the resolved principal SID, and missing target names.
Each object retains its raw security descriptor, owner/group SID, control bits,
and ordered ACEs. Standard/object allow and deny ACEs have numeric masks, flags,
trustee SIDs, inheritance fields, and object GUIDs. Other ACE types retain raw
bytes and `supported=false`; malformed descriptors fail with the raw bytes retained.

Filters select ACE indices in `matches` without removing the full ACE evidence.
`ACE_TYPE=all` includes allow/deny matches. `RIGHTS=DCSync` selects both replication
GUIDs; matching either alone does not establish DCSync access. Matches do not
evaluate effective permissions, token groups, or deny interactions. Inherit-only
ACEs remain identifiable, and empty, null, and absent DACLs are distinct.

`ACTION=backup` writes a declared artifact under `NXC_PATH/logs/daclread`, keeping
the existing `sd` hex and `dn` JSON format. Missing/unreadable descriptors and
LDAP errors are failures, distinct from an absent target or no matching ACEs.
CLI display now uses exact SIDs and numeric masks/GUIDs; it does not run per-ACE
name-resolution searches. The original `TARGET`, `TARGET_DN`, and `PRINCIPAL`
name lookups remain available.
`TARGET_DN` now queries the exact object with BASE scope, including objects in
the Configuration partition, then restores the LDAP session's previous scope.
`PRINCIPAL_SID` selects a known trustee SID directly, such as the built-in
Anonymous Logon SID `S-1-5-7`; choose it or `PRINCIPAL`, not both.

The GOAD ACL inventory reads `examples/playbooks/goad_acl_manifest.json`, a
secret-free snapshot of every explicit ACL entry in the deployed source config.
Run it separately against Kingslanding `10.60.0.10`, Winterfell `10.60.0.11`,
and Meereen `10.60.0.12` with an account for the corresponding domain. Each
result records a source entry, whether a matching live ACE was observed, and
the index of its full `daclread` result in the saved run. Missing targets,
unmatched ACEs, and failed lookups remain separate. For principals classified
as users by the source config, it queries computed `tokenGroups` once per user
and evaluates supported DACL entries under recorded Everyone, Authenticated
Users, and Network logon SID assumptions. `allowed`, `denied`, and `unknown`
assessments are kept per target object. Group, gMSA, and built-in anonymous
principals remain unassessed until their actual tokens and prerequisites are
known. An observed edge or conditional allow is not proof of a completed path.

### Computed groups and conditional DACL assessments

```python
groups = ldap.module("token-groups", principal="tywin.lannister")
print(groups.data.directory_sids)
```

This resolves a user or computer and reads AD's computed `tokenGroups` using a
BASE query, restoring the session's previous search scope afterwards. Results
retain raw attributes, the principal SID, computed group SIDs, and SID history.
Missing `tokenGroups`, malformed binary SIDs, or LDAP errors fail the result;
an unresolved principal returns `negative`. This performs one targeted expansion
per call. [AD computes this attribute through transitive group expansion and
requires a Global Catalog](https://learn.microsoft.com/en-us/windows/win32/adschema/a-tokengroups).

`nxc.playbooks.access.assess_dacl` accepts a decoded descriptor, enabled SIDs,
requested mask, and optional object GUID, target SID, and deny-only SIDs. It
processes supported allow/deny ACEs in stored order against remaining rights.
Results include `allowed`, `denied`, or `unknown`, the reason, and contributing
ACE indices. Deny-only SIDs never grant access, even if also supplied as enabled.
Unresolved property sets, owner semantics, or unsupported ACEs return `unknown`
when they could affect the result.

An `allowed` assessment is conditional on the supplied SIDs and supported DACL
semantics. Directory groups alone are not a complete Windows token. This helper
does not evaluate privileges, restricted tokens, trust filtering, SACL policy,
or operation-specific constraints. Keep the SID assumptions with any assessment.
The GOAD ACL example records Everyone, Authenticated Users, and Network as
explicit logon assumptions; group edges awaiting membership changes remain
unassessed, and `transitions_executed` stays false.

### GOAD membership and host groups

`goad_group_inventory.py` checks each configured direct directory membership
on one GOAD DC at a time. It records the group and member SIDs, the full
`ldap.groups()` result index, and whether a member is direct, primary, missing,
or a foreign-security-principal SID awaiting correlation. `goad_group_reconcile.py`
joins the three saved results by SID without making network requests, then
writes `goad-membership-graph.json` under `NXC_PATH/playbooks` by default.
Only observed edges enter the graph; source mismatches remain in `unresolved`.
`goad_privileged_membership.py` reads that graph and checks candidate Domain
Admin users against AD's computed `tokenGroups` on each DC.

```sh
nxc playbook examples/playbooks/goad_group_inventory.py 10.60.0.12 -u jorah.mormont -p 'H0nnor!' -d essos.local --dns-server 10.60.0.12
```

`goad_local_group_inventory.py` checks the source-configured Administrators and
Remote Desktop Users members on one configured host with typed SMB `local_groups()`
results. Use an account with permission to read that host's SAMR aliases. It
records every configured edge and its member SID, including denials and missing
members. SAMR can return unqualified names, so correlate recorded SIDs with
directory identities before treating a member name as a proven domain account.
These inventories enumerate membership; they do not attempt a group change,
RDP login, or privileged command execution.
`goad_host_reachability.py` joins the saved directory graph and all five host
inventories offline by SID. It includes additional observed SAMR alias members,
labels whether each was configured in the source, and records one shortest
directory-membership path per user and alias member. Its result is a candidate
reachability report, not an exhaustive set of alternate chains or proof of
successful host logon.

### Starting a custom module

Copy `nxc/modules/example_module.py` into `NXC_PATH/modules`, rename both the
file and `NXCModule.name`, and implement its hook. The original `example_module`
name is intentionally excluded from discovery. The example declares its
result dataclass and returns a skipped result because it performs no remote
operation. It supports SMB as a starting point; set `supported_protocols` to
the protocols your implementation actually supports. Use `on_admin_login`
when administrative privileges are required.

Use the supplied connection and return observed values in `data`. Use
`context.playbook` and `context.credential` for a secondary protocol session
when a stored credential reference is available. Every executed hook and every
return path must return the declared data type. Human-readable log messages do
not substitute for those fields. User-installed modules without a dataclass
`result_type` fail before option parsing or hook execution in playbooks, including
custom modules that override a built-in name. Ordinary CLI module use is unchanged.
Built-in modules without a semantic contract still have captured-result support
during this implementation; their conversion
remains required before the full all-module result requirement is complete.

# Configuration

[Paths](#paths) • [Profiles and credentials](#profiles-and-credentials) • [Selection and overrides](#selection-and-overrides) • [Environment](#environment) • [Regions and proxies](#regions-and-proxies)

## Paths

Run `falcon-axi config path` to report the config file and write-journal paths without contacting Falcon.
`--config <path>` overrides `FALCON_AXI_CONFIG`, which overrides the platform default.

| Platform | Config file | RTR journal |
| --- | --- | --- |
| Linux / macOS | `~/.config/falcon-axi/config.json` | `~/.local/state/falcon-axi/writes.log` |
| Windows | `%APPDATA%\falcon-axi\config.json` | `%LOCALAPPDATA%\falcon-axi\writes.log` |

On POSIX, absolute `XDG_CONFIG_HOME` and `XDG_STATE_HOME` replace the corresponding roots; relative values are ignored.
Windows ignores XDG variables and falls back to `~/AppData/Roaming` and `~/AppData/Local` when the respective environment variables are unset.
`FALCON_AXI_WRITE_LOG` overrides the journal path.
RTR execution requires a private, durable journal; see [RTR operator guidance](read-only.md#rtr-operator-guidance).

## Profiles and credentials

A complete environment profile uses `FALCON_AXI_CLIENT_ID` and `FALCON_AXI_CLIENT_SECRET` together.
Supply them through a secret manager or protected shell environment, never command arguments or agent chat.
For named profiles, create `config.json` locally using this synthetic template:

```json
{
  "version": 1,
  "defaultProfile": "triage",
  "profiles": {
    "triage": {
      "region": "us-1",
      "clientId": "<client-id>",
      "clientSecret": {"env": "FALCON_AXI_CLIENT_SECRET"}
    }
  }
}
```

Replace the client ID only in your local configuration.
Use `{"file":"/absolute/local/path"}` to reference a UTF-8 secret file, or `{"env":"YOUR_SECRET_VARIABLE"}` for another environment variable.
Inline secrets are rejected.
On POSIX, secret files require mode 0400 or 0600; config files must not be group/world writable, and both must be owned by you.
On Windows, links and reparse points are rejected; `auth status` also checks the protected user/SYSTEM/Administrators DACL.

```sh
falcon-axi profile list
falcon-axi auth status --profile triage
```

`profile list` reads local configuration without resolving secrets or contacting Falcon.
`auth status` resolves credentials and authenticates against Falcon without printing credential values.
Tokens are held in memory for an invocation; no persistent token cache is written.

## Selection and overrides

Selection order is `--profile`, `FALCON_AXI_PROFILE`, a complete environment profile, `defaultProfile`, then the only configured profile.
A partial environment credential pair fails instead of falling back.
An explicitly selected profile ignores environment credential fields except its named SecretRefs.
`FALCON_AXI_REGION` and `FALCON_AXI_MEMBER_CID` apply to the environment profile, not named file profiles.
`--region` and `--member-cid` override selected profile fields; `--no-member-cid` clears inherited child-tenant selection.
Tenant discovery is not provided.

## Environment

The [README environment table](../README.md#configuration) lists the CLI's configuration and host-detection inputs.
No credentials, profile, or child tenant are selected by default when no usable source exists.
The read-only switch defaults to `false` and accepts `1` / `true` or `0` / `false`, case-insensitively; other values fail with `CONFIG_INVALID` before authentication.
When enabled, it blocks `search start`, `search stop`, `identity activity`, `host usb`, `malquery search`, and RTR execution.
Fixed read-only Identity GraphQL queries, search status, passive RTR history, and local previews remain available.

Deprecated aliases emit a stderr warning, and their replacements win when both are set:

| Deprecated | Replacement |
| --- | --- |
| `FALCON_CLIENT_ID` | `FALCON_AXI_CLIENT_ID` |
| `FALCON_CLIENT_SECRET` | `FALCON_AXI_CLIENT_SECRET` |
| `FALCON_MEMBER_CID` | `FALCON_AXI_MEMBER_CID` |
| `FALCON_BASE_URL` | `FALCON_AXI_REGION` |
| `FALCON_PROXY_URL` | `FALCON_AXI_PROXY_URL` |

`HOME` and `PATH` support home-directory and hook-binary discovery.
Host markers only select skill-install hints; `CLAUDE_CONFIG_DIR` and `PI_CODING_AGENT_DIR` override skill-discovery locations.
OpenCode skill discovery uses `XDG_CONFIG_HOME` when set, otherwise `~/.config`.
Hook installation uses the fixed targets in [agent integration](agent-integration.md), independently of those discovery overrides.
The Windows file-permission checker sets `FALCON_AXI_ACL_PATH` internally for its child process; it is not a user configuration input.

## Regions and proxies

`region` accepts `us-1` (default), `us-2`, `eu-1`, `us-gov-1`, or a full Falcon base URL.
Unknown hosts require explicit `--allow-unknown-origin` in the same invocation.
URLs must use HTTPS and cannot contain user information, ports, queries, fragments, or paths beyond `/`.
Region discovery is automatic only among trusted Falcon destinations; redirects are refused.
`FALCON_AXI_PROXY_URL` configures the proxy used for HTTPS requests.
API requests send credentials to Falcon's OAuth endpoint and query inputs to the selected Falcon cloud through that proxy when configured.
Use only the [permissions](commands.md#api-client-permissions) required by your commands and product licensing.

# Security

Report suspected vulnerabilities privately through [GitHub vulnerability reporting](https://github.com/knowttl/falcon-axi/security/advisories/new).
If that channel is unavailable, open an issue requesting a private reporting channel without disclosing exploit details or sensitive data.
Include the affected command, installed version from `falcon-axi --version`, and a minimal synthetic reproduction when possible.

Never include credentials, tokens, tenant CIDs, captured Falcon responses, host identifiers, or personal data in public issues or pull requests.
Credentials and standalone CID fields are redacted, but composite detection IDs retain their embedded tenant CID.
Treat security findings and investigation output as sensitive even after redaction.
See the [design stance](docs/design/v1.md#0-invariant-r-v1-is-read-only-with-five-captain-granted-exceptions) and [shipped enforcement](docs/read-only.md) for the command boundary, the write gate, guarded RTR execution, and recovery guidance.

# vuln show

vuln show <id>            details for one Spotlight vulnerability record

```text
uvx falcon-axi vuln show <id>

Reads one Spotlight vulnerability record by the id returned by vuln list.
A CVE identifier can match many records; use the Spotlight record id here.
Includes CVE description and score, host details, status, product, and timestamps.
Remediation and evaluation logic are not expanded.

Example: uvx falcon-axi vuln show <id>

This command is read-only and requires Vulnerabilities:read.
```

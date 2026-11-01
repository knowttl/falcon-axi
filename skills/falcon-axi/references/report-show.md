# report show

report show <id>          the detail for one intelligence report

```text
npx -y @knowttl/falcon-axi report show <id> [--full]

--full       print text fields without truncation (default 800 characters per field)

Reads the full report record using an identifier from `npx -y @knowttl/falcon-axi report list`.
No PDF, CSV, or rule file is downloaded or written.
Examples:
  npx -y @knowttl/falcon-axi report show 123456
  npx -y @knowttl/falcon-axi report show 123456 --full

This command is read-only and requires Reports (Falcon Intelligence):read (Falcon Intelligence subscription).
```

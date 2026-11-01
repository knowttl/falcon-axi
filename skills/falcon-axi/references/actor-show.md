# actor show

actor show <id>           the detail for one intelligence actor

```text
npx -y @knowttl/falcon-axi actor show <id> [--full] [--mitre]

--full       print text fields without truncation (default 800 characters per field)
--mitre      also read this actor's JSON MITRE ATT&CK mappings

Reads the full actor record using an identifier from `npx -y @knowttl/falcon-axi actor list`.
No PDF, CSV, or rule file is downloaded or written.
Examples:
  npx -y @knowttl/falcon-axi actor show 123456
  npx -y @knowttl/falcon-axi actor show 123456 --full

This command is read-only and requires Actors (Falcon Intelligence):read (Falcon Intelligence subscription).
```

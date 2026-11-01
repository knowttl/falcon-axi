# exclusion show

exclusion show <id>       the full exclusion record for a required --type

```text
npx -y @knowttl/falcon-axi@next exclusion show <id> --type ml|ioa|sensor-visibility|certificate

--type       required; use the same type as the list that returned the id
Reads the full exclusion record with the same read scope as exclusion list.
Examples:
  npx -y @knowttl/falcon-axi@next exclusion show synthetic-exclusion-01 --type ml
  npx -y @knowttl/falcon-axi@next exclusion show synthetic-exclusion-02 --type certificate
```

# detection process

detection process <id>    process lineage recorded on one detection

```text
uvx falcon-axi detection process <composite id> [--full]

--full       print command lines without the default 800-character truncation

Show the triggering process, parent, and grandparent recorded on the alert.
Rows contain relation, filename, filepath, cmdline, sha256, and process_id.
triggering_process_graph_id is the alert's graph pivot; this view does not fetch a graph.
Absent ancestors and alerts without a process are stated explicitly.
Examples:
  uvx falcon-axi detection process 'ldt:synthetic-agent:1001'
  uvx falcon-axi detection process 'ldt:synthetic-agent:1001' --full

This command is read-only and requires only Alerts:read.
```

# S02/S03 verification amendments

The S02/S03 slices retain the approved credential/parser and passive investigation boundaries.
Those slices add no setup, hook-writing, RTR execution or live-tenant capability.
The S01 primitive and DNS settlement amendments remain binding.

## Installed setup ownership

Move only `test_installed_setup_is_opt_in_repeatable_and_repairs_relocation` from SR-206/S03 to S12.
Plan S12 owns installation and hooks.
The test installs agent hook files, executes the hooks, checks unchanged repeat writes and repairs executable relocation.
Those observations require the S12 implementation and cannot be replaced by an S03 package-read assertion.
The two investigation members of SR-206 remain in S03.
The transferred symbol remains pending and required in S12 and the final S13 gate.
The committed migration coverage ledger records the single-symbol reassignment.
All other S02/S03 ownership remains unchanged.

Move only `test_host_group_member_cursor_rejects_a_different_group` from SR-125/S03 to S04.
Plan S04 owns host-group endpoint inventory.
This standalone symbol requires a successful `host-group members` read before checking cross-group cursor refusal.
The already-correct parameter selections in SR-123 and SR-125 remain unchanged.
The moved symbol is covered by `S04/S05 host-group member cursor rejects a different group` in `tests/typescript/s04-s05.test.ts` and remains required in S13.
Apply the same ownership rule to a later single-test mismatch: record the move to its existing plan owner and retain the final S13 requirement.
A change that leaves a requirement unowned or changes scope requires a separate decision.

## Temporary discovery expectations

The partial TypeScript surface must not advertise commands owned by later slices.
Every affected golden scenario carries an explicit `typescriptMigration` record describing the exact omitted suggestion or narrowed discovery output.
The comparison derives these expectations from the retained origin documents and frozen owned-command list, never from candidate output.
The Python expected documents remain unchanged.
S08-S10 restored search and Identity navigation, setup guidance for search, and write-labelled scope guidance.
The remaining exceptions are:

| Affected scenarios | Temporary difference | Restore when |
| --- | --- | --- |
| `home-view-skill-hint` | Omit installation guidance for the full Python skill. | S12 delivers the candidate's generated skill. |
| `help-top`, `unknown-command`, `scopes` | Restrict command names, summaries and the scope matrix to frozen delivered commands. | Each additional command ships. |

Restore each original discovery entry when its target ships and remove its temporary annotation.
S13 must compare the complete original documents with no TypeScript discovery exceptions.
These annotations authorize no ordinary behavior, error, pagination, identity or redaction difference.

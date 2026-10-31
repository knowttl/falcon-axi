# TypeScript S01 feasibility status

The migration branch preserves the Python implementation while evaluating a Node 24 TypeScript replacement.
This initial increment is a failed feasibility probe, not an installed replacement CLI.
The npm scaffold is private and has no executable entry point.
No runtime dependency or native adapter has been selected.

The TypeScript checks use Node 24.14.0, npm 11.9.0 and exact locked development dependencies.
Run `npm ci --ignore-scripts` and `npm run verify` for strict compilation and formatting.
On Linux with user namespaces enabled, run `npm run check:slice -- --slice S01 --paths native --offline` to reproduce the primitive STOP under a process-level network namespace with no external interfaces.
That command exits 1 deliberately when the rejected Node-only approach follows the replaced ancestor.
It is not a passing S01 gate.
Other selectors and platforms fail with exit 2 rather than silently claiming coverage.

The probe retains a directory descriptor, checks its ownership and permissions, then deterministically replaces its pathname with a symlink before opening the journal with `O_NOFOLLOW`.
The append reaches the replacement directory even though the final file passes ownership, link-count and mode checks.
The original retained directory remains unchanged.
The final-symlink negative control is refused, and file/directory fsync succeeds.
These observations show why ordinary path opens cannot replace descriptor-relative traversal in the existing RTR journal.
They do not show that a future native adapter is impossible.

The inspected `fs-ext@2.1.1` API supplies flock but no descriptor-relative open.
The inspected `fs-native-extensions@1.5.3` API supplies locking but no descriptor-relative open either.
Its Linux lock implementation uses OFD fcntl locking; interoperability with the existing flock journal has not been proved.
Neither package was adopted or executed.
Node's public filesystem API does not supply the missing complete primitive interface.
Sources: [Node filesystem API](https://nodejs.org/download/release/v24.14.0/docs/api/fs.html), [fs-ext](https://github.com/baudehlo/node-fs-ext), and [fs-native-extensions](https://github.com/holepunchto/fs-native-extensions).

The required compiled narrow primitive adapter remains unproved, including retained-inode locking and interrupted durable append.
S01 therefore remains blocked at its primitive STOP gate.
Transport, output, packaging, credential injection and real local Artium journeys remain unrun.
No live tenant request, host deployment, release action or workflow change is included.
Resumption requires a reviewed narrow native adapter candidate with descriptor-relative traversal and compatible locking, followed by the actual primitive proof and the remaining S01 checks.

# S01 primitive feasibility amendment

The RTR filesystem primitive proof is decoupled from S01.
S01 completes the packaged detection read, transport, OAuth, output parity and real local Artium read proof.
Transport and output feasibility remain STOP gates.
The negative Node-only primitive probe is retained as evidence and excluded from S01 pass criteria.

Before S11, a separate native-addon slice must provide descriptor-relative openat with O_NOFOLLOW, nonblocking flock on the retained inode, interrupted-append handling and file/directory fsync durability through a minimal reviewed compiled interface.
The addon must be prebuilt for Linux and Windows.
Reads, preview and Windows loading must not depend on POSIX-only binaries.
No Python RTR safety guarantee is loosened, and a Linux-only /proc workaround is excluded.

## DNS deadline settlement

The one-shot CLI and the hosted worker flush the safe result and terminate their process when the invocation completes, including at the invocation deadline.
This settles the process inside the budget even when an OS getaddrinfo call remains pending after request cancellation.
The system resolver retains files+dns NSS and hosts-file behaviour, matching Python.
A c-ares resolver and a relaxed budget are excluded.
Transport and output feasibility remain STOP gates.

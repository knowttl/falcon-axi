"""Ordered command registry assembled from domain declarations."""

from falcon_axi import account, cve, detection, diagnostics, host, identity, scopes, search, vuln

# Keep historical discovery and scope ordering while identity spans two positions.
COMMAND_SPECS = {
    spec.name: spec
    for group in (
        detection.COMMAND_SPECS,
        host.COMMAND_SPECS,
        account.COMMAND_SPECS,
        vuln.COMMAND_SPECS,
        cve.COMMAND_SPECS,
        identity.COMMAND_SPECS[:1],
        search.COMMAND_SPECS,
        identity.COMMAND_SPECS[1:],
        diagnostics.COMMAND_SPECS,
        scopes.COMMAND_SPECS,
    )
    for spec in group
}
COMMANDS = tuple(COMMAND_SPECS)
SUBCOMMANDS: dict[str, tuple[str, ...]] = {}
for name in COMMANDS:
    parts = name.split()
    for index in range(1, len(parts)):
        parent, child = " ".join(parts[:index]), parts[index]
        if child not in SUBCOMMANDS.get(parent, ()):
            SUBCOMMANDS[parent] = (*SUBCOMMANDS.get(parent, ()), child)

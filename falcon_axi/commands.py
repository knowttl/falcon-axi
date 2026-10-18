"""Ordered command registry assembled from domain declarations."""

from falcon_axi import (
    account,
    case,
    correlation_rule,
    cve,
    detection,
    diagnostics,
    firewall,
    host,
    identity,
    ioa,
    scopes,
    search,
    vuln,
)

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
        firewall.COMMAND_SPECS,
        ioa.COMMAND_SPECS,
        correlation_rule.COMMAND_SPECS,
        case.COMMAND_SPECS,
        diagnostics.COMMAND_SPECS,
        scopes.COMMAND_SPECS,
    )
    for spec in group
}
COMMANDS = tuple(COMMAND_SPECS)
SUBCOMMANDS: dict[str, tuple[str, ...]] = {}
for name in COMMANDS:
    words = name.split()
    for index in range(1, len(words)):
        noun, verb = " ".join(words[:index]), words[index]
        if verb not in SUBCOMMANDS.get(noun, ()):
            SUBCOMMANDS[noun] = (*SUBCOMMANDS.get(noun, ()), verb)

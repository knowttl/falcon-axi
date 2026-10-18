"""Ordered command registry assembled from domain declarations."""

from falcon_axi import account, cloud_asset, cloud_risk, cve, detection, diagnostics, host, identity, indicator, iom, scopes, search, vuln

# Keep historical discovery and scope ordering while identity spans two positions.
COMMAND_SPECS = {
    spec.name: spec
    for group in (
        detection.COMMAND_SPECS,
        host.COMMAND_SPECS,
        account.COMMAND_SPECS,
        vuln.COMMAND_SPECS,
        cve.COMMAND_SPECS,
        indicator.COMMAND_SPECS,
        identity.COMMAND_SPECS[:1],
        search.COMMAND_SPECS,
        identity.COMMAND_SPECS[1:],
        cloud_asset.COMMAND_SPECS,
        iom.COMMAND_SPECS,
        cloud_risk.COMMAND_SPECS,
        diagnostics.COMMAND_SPECS,
        scopes.COMMAND_SPECS,
    )
    for spec in group
}
COMMANDS = tuple(COMMAND_SPECS)
SUBCOMMANDS: dict[str, tuple[str, ...]] = {}
for name in COMMANDS:
    noun, separator, verb = name.partition(" ")
    if separator:
        SUBCOMMANDS[noun] = (*SUBCOMMANDS.get(noun, ()), verb)

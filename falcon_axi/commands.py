"""Ordered command registry assembled from domain declarations."""

from falcon_axi import (
    account,
    classification,
    cloud_asset,
    cloud_risk,
    container,
    cve,
    data_policy,
    detection,
    diagnostics,
    discover,
    exclusion,
    host,
    host_group,
    identity,
    image,
    indicator,
    intel,
    ioc,
    iom,
    policy,
    quarantine,
    recon_notification,
    recon_record,
    recon_rule,
    scopes,
    search,
    sensor_usage,
    serverless,
    setup,
    shield,
    vuln,
)

# Keep historical discovery and scope ordering while identity spans two positions.
COMMAND_SPECS = {
    spec.name: spec
    for group in (
        detection.COMMAND_SPECS,
        host.COMMAND_SPECS,
        account.COMMAND_SPECS,
        discover.COMMAND_SPECS,
        vuln.COMMAND_SPECS,
        cve.COMMAND_SPECS,
        intel.COMMAND_SPECS,
        indicator.COMMAND_SPECS,
        container.COMMAND_SPECS,
        image.COMMAND_SPECS,
        serverless.COMMAND_SPECS,
        classification.COMMAND_SPECS,
        data_policy.COMMAND_SPECS,
        identity.COMMAND_SPECS[:1],
        search.COMMAND_SPECS,
        identity.COMMAND_SPECS[1:],
        ioc.COMMAND_SPECS,
        host_group.COMMAND_SPECS,
        policy.COMMAND_SPECS,
        cloud_asset.COMMAND_SPECS,
        iom.COMMAND_SPECS,
        cloud_risk.COMMAND_SPECS,
        shield.COMMAND_SPECS,
        exclusion.COMMAND_SPECS,
        quarantine.COMMAND_SPECS,
        diagnostics.COMMAND_SPECS,
        scopes.COMMAND_SPECS,
        sensor_usage.COMMAND_SPECS,
        recon_rule.COMMAND_SPECS,
        recon_notification.COMMAND_SPECS,
        recon_record.COMMAND_SPECS,
        setup.COMMAND_SPECS,
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

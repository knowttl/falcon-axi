"""The mechanical form of Invariant R (docs/design/v1.md §3.3, §14.5)."""

import dataclasses

import pytest

from falcon_axi.core import CliError
from falcon_axi.transport.operations import (
    GRAPHQL_QUERY_IDS,
    MUTATION_ROUTE_PATTERNS,
    OPERATION_IDS,
    OPERATIONS,
    SEARCH_LIFECYCLE_IDS,
    operation,
    registered_scopes,
)

#: Operations whose §2.2 corroboration is falconpy's generated table plus PSFalcon, because falcon-mcp
#: has no tool for them, mapped to the falconpy endpoint module that lists each one.
NO_FALCON_MCP_TOOL = {
    "QueryMalwareEntities": "_intel",
    "GetMalwareEntities": "_intel",
    "get_policy_rules_query": "_identity_protection",
    "get_policy_rules": "_identity_protection",
    "query_iot_hostsV2": "_discover",
    "get_iot_hosts": "_discover",
    "GetCombinedImages": "_container_images",
    "DevicesRanOn": "_iocs",
    "ProcessesRanOn": "_iocs",
    "get_hosts": "_discover",
    "query_logins": "_discover",
    "get_logins": "_discover",
    "QueryGetNetworkAddressHistoryV1": "_hosts",
    "GetSensorDetails": "_identity_protection",
    "QuerySensorsByFilter": "_identity_protection",
    "getVulnerabilities": "_spotlight_vulnerabilities",
    "QueryVulnerabilities": "_intel",
    "GetIntelIndicatorEntities": "_intel",
    "GetVulnerabilities": "_intel",
    "GetIntelActorEntities": "_intel",
    "GetIntelReportEntities": "_intel",
    "QueryDeviceLoginHistoryV2": "_hosts",
    "query_accounts": "_discover",
    "get_accounts": "_discover",
}

EXPECTED = {
    "QueryMalwareEntities": {
        "method": "GET",
        "path": "/intel/combined/malware/v1",
        "scopes": ("Malware Families (Falcon Intelligence):read",),
        "effect": "read",
        "doc_scope": "Malware Families (Falcon Intelligence): READ",
    },
    "GetMalwareEntities": {
        "method": "GET",
        "path": "/intel/entities/malware/v1",
        "scopes": ("Malware Families (Falcon Intelligence):read",),
        "effect": "read",
        "doc_scope": "Malware Families (Falcon Intelligence): READ",
    },
    "get_policy_rules_query": {
        "method": "GET",
        "path": "/identity-protection/queries/policy-rules/v1",
        "scopes": ("Identity Protection Policy Rules:read",),
        "effect": "read",
        "doc_scope": "Identity Protection Policy Rules: READ",
    },
    "get_policy_rules": {
        "method": "GET",
        "path": "/identity-protection/entities/policy-rules/v1",
        "scopes": ("Identity Protection Policy Rules:read",),
        "effect": "read",
        "doc_scope": "Identity Protection Policy Rules: READ",
    },
    "query_iot_hostsV2": {
        "method": "GET",
        "path": "/discover/queries/iot-hosts/v2",
        "scopes": ("Falcon Discover IoT:read",),
        "effect": "read",
        "doc_scope": "Falcon Discover IoT: READ",
    },
    "get_iot_hosts": {
        "method": "GET",
        "path": "/discover/entities/iot-hosts/v1",
        "scopes": ("Falcon Discover IoT:read",),
        "effect": "read",
        "doc_scope": "Falcon Discover IoT: READ",
    },
    "query_rules": {
        "method": "GET",
        "path": "/fwmgr/queries/rules/v1",
        "scopes": ("Firewall Management:read",),
        "effect": "read",
        "doc_scope": "Firewall management: READ",
    },
    "get_rules": {
        "method": "GET",
        "path": "/fwmgr/entities/rules/v1",
        "scopes": ("Firewall Management:read",),
        "effect": "read",
        "doc_scope": "Firewall management: READ",
    },
    "query_rule_groups": {
        "method": "GET",
        "path": "/fwmgr/queries/rule-groups/v1",
        "scopes": ("Firewall Management:read",),
        "effect": "read",
        "doc_scope": "Firewall management: READ",
    },
    "get_rule_groups": {
        "method": "GET",
        "path": "/fwmgr/entities/rule-groups/v1",
        "scopes": ("Firewall Management:read",),
        "effect": "read",
        "doc_scope": "Firewall management: READ",
    },
    "query_rule_groups_full": {
        "method": "GET",
        "path": "/ioarules/queries/rule-groups-full/v1",
        "scopes": ("Custom IOA Rules:read",),
        "effect": "read",
        "doc_scope": "Custom IOA rules: READ",
    },
    "combined_rules_get_v2": {
        "method": "GET",
        "path": "/correlation-rules/combined/rules/v2",
        "scopes": ("Correlation Rules:read",),
        "effect": "read",
        "doc_scope": "Correlation Rules: READ",
    },
    "queries_cases_get_v1": {
        "method": "GET",
        "path": "/cases/queries/cases/v1",
        "scopes": ("Cases:read",),
        "effect": "read",
        "doc_scope": "Cases: READ",
    },
    "entities_cases_post_v2": {
        "method": "POST",
        "path": "/cases/entities/cases/v2",
        "scopes": ("Cases:read",),
        "effect": "read",
        "doc_scope": "Cases: READ",
    },
    "exclusions_search_v2": {
        "method": "GET",
        "path": "/exclusions/queries/exclusions/v2",
        "scopes": ("Machine Learning Exclusions:read",),
        "effect": "read",
        "doc_scope": "Machine Learning Exclusions: READ",
    },
    "exclusions_get_v2": {
        "method": "GET",
        "path": "/exclusions/entities/exclusions/v2",
        "scopes": ("Machine Learning Exclusions:read",),
        "effect": "read",
        "doc_scope": "Machine Learning Exclusions: READ",
    },
    "ss_ioa_exclusions_search_v2": {
        "method": "GET",
        "path": "/exclusions/queries/ss-ioa-exclusions/v2",
        "scopes": ("IOA Exclusions:read",),
        "effect": "read",
        "doc_scope": "IOA Exclusions: READ",
    },
    "ss_ioa_exclusions_get_v2": {
        "method": "GET",
        "path": "/exclusions/entities/ss-ioa-exclusions/v2",
        "scopes": ("IOA Exclusions:read",),
        "effect": "read",
        "doc_scope": "IOA Exclusions: READ",
    },
    "querySensorVisibilityExclusionsV1": {
        "method": "GET",
        "path": "/policy/queries/sv-exclusions/v1",
        "scopes": ("Sensor Visibility Exclusions:read",),
        "effect": "read",
        "doc_scope": "Sensor Visibility Exclusions: READ",
    },
    "getSensorVisibilityExclusionsV1": {
        "method": "GET",
        "path": "/policy/entities/sv-exclusions/v1",
        "scopes": ("Sensor Visibility Exclusions:read",),
        "effect": "read",
        "doc_scope": "Sensor Visibility Exclusions: READ",
    },
    "cb_exclusions_query_v1": {
        "method": "GET",
        "path": "/exclusions/queries/cert-based-exclusions/v1",
        "scopes": ("Machine Learning Exclusions:read",),
        "effect": "read",
        "doc_scope": "Machine Learning Exclusions: READ",
    },
    "cb_exclusions_get_v1": {
        "method": "GET",
        "path": "/exclusions/entities/cert-based-exclusions/v1",
        "scopes": ("Machine Learning Exclusions:read",),
        "effect": "read",
        "doc_scope": "Machine Learning Exclusions: READ",
    },
    "QueryQuarantineFiles": {
        "method": "GET",
        "path": "/quarantine/queries/quarantined-files/v1",
        "scopes": ("Quarantined Files:read",),
        "effect": "read",
        "doc_scope": "Quarantined Files: READ",
    },
    "GetQuarantineFiles": {
        "method": "POST",
        "path": "/quarantine/entities/quarantined-files/GET/v1",
        "scopes": ("Quarantined Files:read",),
        "effect": "read",
        "doc_scope": "Quarantined Files: READ",
    },
    "GetSensorUsageWeekly": {
        "method": "GET",
        "path": "/billing-dashboards-usage/aggregates/weekly-average/v1",
        "scopes": ("Sensor Usage:read",),
        "effect": "read",
        "doc_scope": "Sensor Usage: READ",
    },
    "QueryRulesV1": {
        "method": "GET",
        "path": "/recon/queries/rules/v1",
        "scopes": ("Monitoring rules (Falcon Intelligence Recon):read",),
        "effect": "read",
        "doc_scope": "Monitoring rules (Falcon Intelligence Recon): READ",
    },
    "GetRulesV1": {
        "method": "GET",
        "path": "/recon/entities/rules/v1",
        "scopes": ("Monitoring rules (Falcon Intelligence Recon):read",),
        "effect": "read",
        "doc_scope": "Monitoring rules (Falcon Intelligence Recon): READ",
    },
    "QueryNotificationsV1": {
        "method": "GET",
        "path": "/recon/queries/notifications/v1",
        "scopes": ("Monitoring rules (Falcon Intelligence Recon):read",),
        "effect": "read",
        "doc_scope": "Monitoring rules (Falcon Intelligence Recon): READ",
    },
    "GetNotificationsDetailedV1": {
        "method": "GET",
        "path": "/recon/entities/notifications-detailed/v1",
        "scopes": ("Monitoring rules (Falcon Intelligence Recon):read",),
        "effect": "read",
        "doc_scope": "Monitoring rules (Falcon Intelligence Recon): READ",
    },
    "QueryNotificationsExposedDataRecordsV1": {
        "method": "GET",
        "path": "/recon/queries/notifications-exposed-data-records/v1",
        "scopes": ("Monitoring rules (Falcon Intelligence Recon):read",),
        "effect": "read",
        "doc_scope": "Monitoring rules (Falcon Intelligence Recon): READ",
    },
    "GetNotificationsExposedDataRecordsV1": {
        "method": "GET",
        "path": "/recon/entities/notifications-exposed-data-records/v1",
        "scopes": ("Monitoring rules (Falcon Intelligence Recon):read",),
        "effect": "read",
        "doc_scope": "Monitoring rules (Falcon Intelligence Recon): READ",
    },
    "GetSecurityChecksV3": {
        "method": "GET",
        "path": "/saas-security/entities/checks/v3",
        "scopes": ("SaaS Security:read",),
        "effect": "read",
        "doc_scope": "SaaS Security (Falcon Shield): READ",
    },
    "GetCombinedVulnerabilitiesSARIF": {
        "method": "GET",
        "path": "/lambdas/combined/vulnerabilities/sarif/v1",
        "scopes": ("Falcon Container Image:read",),
        "effect": "read",
        "doc_scope": "Falcon Container Image: READ",
    },
    "ReadContainerCombined": {
        "method": "GET",
        "path": "/container-security/combined/containers/v1",
        "scopes": ("Falcon Container Image:read",),
        "effect": "read",
        "doc_scope": "Falcon Container Image: READ",
    },
    "ReadCombinedVulnerabilities": {
        "method": "GET",
        "path": "/container-security/combined/vulnerabilities/v1",
        "scopes": ("Falcon Container Image:read",),
        "effect": "read",
        "doc_scope": "Falcon Container Image: READ",
    },
    "GetCombinedImages": {
        "method": "GET",
        "path": "/container-security/combined/image-assessment/images/v1",
        "scopes": ("Falcon Container Image:read",),
        "effect": "read",
        "doc_scope": "Falcon Container Image: READ",
    },
    "queries_classification_get_v2": {
        "method": "GET",
        "path": "/data-protection/queries/classifications/v2",
        "scopes": ("Data Protection:read",),
        "effect": "read",
        "doc_scope": "Data Protection: READ",
    },
    "entities_classification_get_v2": {
        "method": "GET",
        "path": "/data-protection/entities/classifications/v2",
        "scopes": ("Data Protection:read",),
        "effect": "read",
        "doc_scope": "Data Protection: READ",
    },
    "queries_policy_get_v2": {
        "method": "GET",
        "path": "/data-protection/queries/policies/v2",
        "scopes": ("Data Protection:read",),
        "effect": "read",
        "doc_scope": "Data Protection: READ",
    },
    "entities_policy_get_v2": {
        "method": "GET",
        "path": "/data-protection/entities/policies/v2",
        "scopes": ("Data Protection:read",),
        "effect": "read",
        "doc_scope": "Data Protection: READ",
    },
    "queryCombinedPreventionPolicies": {
        "method": "GET",
        "path": "/policy/combined/prevention/v1",
        "scopes": ("Prevention Policies:read",),
        "effect": "read",
        "doc_scope": "Prevention Policies: READ",
    },
    "queryCombinedPreventionPolicyMembers": {
        "method": "GET",
        "path": "/policy/combined/prevention-members/v1",
        "scopes": ("Prevention Policies:read",),
        "effect": "read",
        "doc_scope": "Prevention Policies: READ",
    },
    "queryCombinedSensorUpdatePoliciesV2": {
        "method": "GET",
        "path": "/policy/combined/sensor-update/v2",
        "scopes": ("Sensor Update Policies:read",),
        "effect": "read",
        "doc_scope": "Sensor Update Policies: READ",
    },
    "queryCombinedSensorUpdatePolicyMembers": {
        "method": "GET",
        "path": "/policy/combined/sensor-update-members/v1",
        "scopes": ("Sensor Update Policies:read",),
        "effect": "read",
        "doc_scope": "Sensor Update Policies: READ",
    },
    "queryCombinedFirewallPolicies": {
        "method": "GET",
        "path": "/policy/combined/firewall/v1",
        "scopes": ("Firewall Management:read",),
        "effect": "read",
        "doc_scope": "Firewall Management: READ",
    },
    "queryCombinedFirewallPolicyMembers": {
        "method": "GET",
        "path": "/policy/combined/firewall-members/v1",
        "scopes": ("Firewall Management:read",),
        "effect": "read",
        "doc_scope": "Firewall Management: READ",
    },
    "queryCombinedDeviceControlPolicies": {
        "method": "GET",
        "path": "/policy/combined/device-control/v1",
        "scopes": ("Device Control Policies:read",),
        "effect": "read",
        "doc_scope": "Device Control Policies: READ",
    },
    "queryCombinedDeviceControlPolicyMembers": {
        "method": "GET",
        "path": "/policy/combined/device-control-members/v1",
        "scopes": ("Device Control Policies:read",),
        "effect": "read",
        "doc_scope": "Device Control Policies: READ",
    },
    "queryCombinedRTResponsePolicies": {
        "method": "GET",
        "path": "/policy/combined/response/v1",
        "scopes": ("Response Policies:read",),
        "effect": "read",
        "doc_scope": "Response Policies: READ",
    },
    "queryCombinedRTResponsePolicyMembers": {
        "method": "GET",
        "path": "/policy/combined/response-members/v1",
        "scopes": ("Response Policies:read",),
        "effect": "read",
        "doc_scope": "Response Policies: READ",
    },
    "queryCombinedContentUpdatePolicies": {
        "method": "GET",
        "path": "/policy/combined/content-update/v1",
        "scopes": ("Content Update Policies:read",),
        "effect": "read",
        "doc_scope": "Content Update Policy: READ",
    },
    "queryCombinedContentUpdatePolicyMembers": {
        "method": "GET",
        "path": "/policy/combined/content-update-members/v1",
        "scopes": ("Content Update Policies:read",),
        "effect": "read",
        "doc_scope": "Content Update Policy: READ",
    },
    "indicator_search_v1": {
        "method": "GET",
        "path": "/iocs/queries/indicators/v1",
        "scopes": ("IOC Management:read",),
        "effect": "read",
        "doc_scope": "IOC Management: READ",
    },
    "indicator_get_v1": {
        "method": "GET",
        "path": "/iocs/entities/indicators/v1",
        "scopes": ("IOC Management:read",),
        "effect": "read",
        "doc_scope": "IOC Management: READ",
    },
    "DevicesRanOn": {
        "method": "GET",
        "path": "/indicators/queries/devices/v1",
        "scopes": ("IOCs (Indicators of Compromise):read",),
        "effect": "read",
        "doc_scope": "IOCs (Indicators of Compromise): READ",
    },
    "ProcessesRanOn": {
        "method": "GET",
        "path": "/indicators/queries/processes/v1",
        "scopes": ("IOCs (Indicators of Compromise):read",),
        "effect": "read",
        "doc_scope": "IOCs (Indicators of Compromise): READ",
    },
    "queryCombinedHostGroups": {
        "method": "GET",
        "path": "/devices/combined/host-groups/v1",
        "scopes": ("Host Groups:read",),
        "effect": "read",
        "doc_scope": "Host groups: READ",
    },
    "queryCombinedGroupMembers": {
        "method": "GET",
        "path": "/devices/combined/host-group-members/v1",
        "scopes": ("Host Groups:read",),
        "effect": "read",
        "doc_scope": "Host groups: READ",
    },
    "combined_hosts": {
        "method": "GET",
        "path": "/discover/combined/hosts/v1",
        "scopes": ("Assets:read",),
        "effect": "read",
        "doc_scope": "Assets: READ",
    },
    "get_hosts": {
        "method": "GET",
        "path": "/discover/entities/hosts/v1",
        "scopes": ("Assets:read",),
        "effect": "read",
        "doc_scope": "Assets: READ",
    },
    "combined_applications": {
        "method": "GET",
        "path": "/discover/combined/applications/v1",
        "scopes": ("Assets:read",),
        "effect": "read",
        "doc_scope": "Assets: READ",
    },
    "query_logins": {
        "method": "GET",
        "path": "/discover/queries/logins/v1",
        "scopes": ("Assets:read",),
        "effect": "read",
        "doc_scope": "Assets: READ",
    },
    "get_logins": {
        "method": "GET",
        "path": "/discover/entities/logins/v1",
        "scopes": ("Assets:read",),
        "effect": "read",
        "doc_scope": "Assets: READ",
    },
    "QueryGetNetworkAddressHistoryV1": {
        "method": "POST",
        "path": "/devices/combined/devices/network-address-history/v1",
        "scopes": ("Hosts:read",),
        "effect": "read",
        "doc_scope": "Hosts: READ",
    },
    "QuerySensorsByFilter": {
        "method": "GET",
        "path": "/identity-protection/queries/devices/v1",
        "scopes": ("Identity Protection Entities:read",),
        "effect": "read",
        "doc_scope": "Identity Protection Entities: READ",
    },
    "GetSensorDetails": {
        "method": "POST",
        "path": "/identity-protection/entities/devices/GET/v1",
        "scopes": ("Identity Protection Entities:read",),
        "effect": "read",
        "doc_scope": "Identity Protection Entities: READ",
    },
    "QueryVulnerabilities": {
        "method": "GET",
        "path": "/intel/queries/vulnerabilities/v1",
        "scopes": ("Vulnerabilities (Falcon Intelligence):read",),
        "effect": "read",
        "doc_scope": "Vulnerabilities (Falcon Intelligence): READ",
    },
    "getVulnerabilities": {
        "method": "GET",
        "path": "/spotlight/entities/vulnerabilities/v2",
        "scopes": ("Vulnerabilities:read",),
        "effect": "read",
        "doc_scope": "Vulnerabilities: READ",
    },
    "QueryIntelActorEntities": {
        "method": "GET",
        "path": "/intel/combined/actors/v1",
        "scopes": ("Actors (Falcon Intelligence):read",),
        "effect": "read",
        "doc_scope": "Actors (Falcon Intelligence): READ",
    },
    "GetIntelActorEntities": {
        "method": "GET",
        "path": "/intel/entities/actors/v1",
        "scopes": ("Actors (Falcon Intelligence):read",),
        "effect": "read",
        "doc_scope": "Actors (Falcon Intelligence): READ",
    },
    "QueryIntelReportEntities": {
        "method": "GET",
        "path": "/intel/combined/reports/v1",
        "scopes": ("Reports (Falcon Intelligence):read",),
        "effect": "read",
        "doc_scope": "Reports (Falcon Intelligence): READ",
    },
    "GetIntelReportEntities": {
        "method": "GET",
        "path": "/intel/entities/reports/v1",
        "scopes": ("Reports (Falcon Intelligence):read",),
        "effect": "read",
        "doc_scope": "Reports (Falcon Intelligence): READ",
    },
    "GetMitreReport": {
        "method": "GET",
        "path": "/intel/entities/mitre-reports/v1",
        "scopes": ("Actors (Falcon Intelligence):read",),
        "effect": "read",
        "doc_scope": "Actors (Falcon Intelligence): READ",
    },
    "QueryIntelIndicatorEntities": {
        "method": "GET",
        "path": "/intel/combined/indicators/v1",
        "scopes": ("Indicators (Falcon Intelligence):read",),
        "effect": "read",
        "doc_scope": "Indicators (Falcon Intelligence): READ",
    },
    "GetIntelIndicatorEntities": {
        "method": "POST",
        "path": "/intel/entities/indicators/GET/v1",
        "scopes": ("Indicators (Falcon Intelligence):read",),
        "effect": "read",
        "doc_scope": "Indicators (Falcon Intelligence): READ",
    },
    "cloud_security_assets_queries": {
        "method": "GET",
        "path": "/cloud-security-assets/queries/resources/v1",
        "scopes": ("Cloud Security API Assets:read",),
        "effect": "read",
        "doc_scope": "Cloud Security API Assets: READ",
    },
    "cloud_security_assets_entities_get": {
        "method": "GET",
        "path": "/cloud-security-assets/entities/resources/v1",
        "scopes": ("Cloud Security API Assets:read",),
        "effect": "read",
        "doc_scope": "Cloud Security API Assets: READ",
    },
    "cspm_evaluations_iom_queries": {
        "method": "GET",
        "path": "/cloud-security-evaluations/queries/ioms/v1",
        "scopes": ("Cloud Security API Detections:read",),
        "effect": "read",
        "doc_scope": "Cloud Security API Detections: READ",
    },
    "cspm_evaluations_iom_entities": {
        "method": "GET",
        "path": "/cloud-security-evaluations/entities/ioms/v1",
        "scopes": ("Cloud Security API Detections:read",),
        "effect": "read",
        "doc_scope": "Cloud Security API Detections: READ",
    },
    "combined_cloud_risks": {
        "method": "GET",
        "path": "/cloud-security-risks/combined/cloud-risks/v1",
        "scopes": ("Cloud Security API Risks:read",),
        "effect": "read",
        "doc_scope": "Cloud Security API Risks: READ",
    },
    "PostAggregatesAlertsV2": {
        "method": "POST",
        "path": "/alerts/aggregates/alerts/v2",
        "scopes": ("Alerts:read",),
        "effect": "read",
        "doc_scope": "Alerts: READ",
    },
    "GetQueriesAlertsV2": {
        "method": "GET",
        "path": "/alerts/queries/alerts/v2",
        "scopes": ("Alerts:read",),
        "effect": "read",
        "doc_scope": "Alerts: READ",
    },
    "PostEntitiesAlertsV2": {
        "method": "POST",
        "path": "/alerts/entities/alerts/v2",
        "scopes": ("Alerts:read",),
        "effect": "read",
        "doc_scope": "Alerts: READ",
    },
    "QueryDevicesByFilter": {
        "method": "GET",
        "path": "/devices/queries/devices/v1",
        "scopes": ("Hosts:read",),
        "effect": "read",
        "doc_scope": "Hosts: READ",
    },
    "PostDeviceDetailsV2": {
        "method": "POST",
        "path": "/devices/entities/devices/v2",
        "scopes": ("Hosts:read",),
        "effect": "read",
        "doc_scope": "Hosts: READ",
    },
    "combinedQueryVulnerabilities": {
        "method": "GET",
        "path": "/spotlight/combined/vulnerabilities/v1",
        "scopes": ("Vulnerabilities:read",),
        "effect": "read",
        "doc_scope": "Vulnerabilities: READ",
    },
    "GetVulnerabilities": {
        "method": "POST",
        "path": "/intel/entities/vulnerabilities/GET/v1",
        "scopes": ("Vulnerabilities (Falcon Intelligence):read",),
        "effect": "read",
        "doc_scope": "Vulnerabilities (Falcon Intelligence): READ",
    },
    "QueryDeviceLoginHistoryV2": {
        "method": "POST",
        "path": "/devices/combined/devices/login-history/v2",
        "scopes": ("Hosts:read",),
        "effect": "read",
        "doc_scope": "Hosts: READ",
    },
    "query_accounts": {
        "method": "GET",
        "path": "/discover/queries/accounts/v1",
        "scopes": ("Assets:read",),
        "effect": "read",
        "doc_scope": "Assets: READ",
    },
    "get_accounts": {
        "method": "GET",
        "path": "/discover/entities/accounts/v1",
        "scopes": ("Assets:read",),
        "effect": "read",
        "doc_scope": "Assets: READ",
    },
    "StartSearchV1": {
        "method": "POST",
        "path": "/humio/api/v1/repositories/{repository}/queryjobs",
        "scopes": ("NGSIEM:write",),
        "effect": "search-lifecycle",
        "doc_scope": "NGSIEM: WRITE",
    },
    "GetSearchStatusV1": {
        "method": "GET",
        "path": "/humio/api/v1/repositories/{repository}/queryjobs/{id}",
        "scopes": ("NGSIEM:read",),
        "effect": "read",
        "doc_scope": "NGSIEM: READ",
    },
    "StopSearchV1": {
        "method": "DELETE",
        "path": "/humio/api/v1/repositories/{repository}/queryjobs/{id}",
        "scopes": ("NGSIEM:write",),
        "effect": "search-lifecycle",
        "doc_scope": "NGSIEM: WRITE",
    },
    "api_preempt_proxy_post_graphql": {
        "method": "POST",
        "path": "/identity-protection/combined/graphql/v1",
        "scopes": ("Identity Protection GraphQL:write",),
        "effect": "graphql-query",
        "doc_scope": "Identity Protection GraphQL: WRITE",
    },
}


def test_the_registry_contains_exactly_the_registered_operations() -> None:
    assert sorted(OPERATIONS) == sorted(EXPECTED)
    assert sorted(OPERATION_IDS) == sorted(EXPECTED)


def test_every_descriptor_equals_its_canonical_value_and_carries_matching_evidence() -> None:
    for id, expected in EXPECTED.items():
        descriptor = OPERATIONS[id]
        assert descriptor.id == id
        assert descriptor.method == expected["method"]
        assert descriptor.path == expected["path"]
        assert descriptor.scopes == expected["scopes"]
        assert descriptor.effect == expected["effect"]
        assert descriptor.evidence.doc_scope == expected["doc_scope"]
        suffix = ": READ" if descriptor.effect == "read" else ": WRITE"
        assert descriptor.evidence.doc_scope.upper().endswith(suffix)
        assert descriptor.evidence.doc_url.startswith("https://")
        citation = descriptor.evidence.falcon_mcp
        if id in NO_FALCON_MCP_TOOL:
            assert f"falcon-mcp has no tool for {id}" in citation
            assert f"falconpy/_endpoint/{NO_FALCON_MCP_TOOL[id]}.py maps {id} to " in citation
            assert "PSFalcon " in citation
            assert "api_scopes.py" not in citation
        else:
            assert "api_scopes.py" in citation and "maps " in citation


def test_no_registered_path_matches_a_known_mutation_route() -> None:
    for descriptor in OPERATIONS.values():
        for pattern in MUTATION_ROUTE_PATTERNS:
            assert pattern.search(descriptor.path) is None, f"{descriptor.id} matches {pattern.pattern}"


def test_every_registered_scope_is_a_read_scope_outside_the_two_captain_exceptions() -> None:
    assert SEARCH_LIFECYCLE_IDS == {"StartSearchV1", "StopSearchV1"}
    assert GRAPHQL_QUERY_IDS == {"api_preempt_proxy_post_graphql"}
    exceptions = SEARCH_LIFECYCLE_IDS | GRAPHQL_QUERY_IDS
    for id in EXPECTED:
        for scope in registered_scopes([id]):
            assert scope.endswith(":write" if id in exceptions else ":read")
    assert registered_scopes(list(SEARCH_LIFECYCLE_IDS)) == ("NGSIEM:write",)
    assert registered_scopes(list(GRAPHQL_QUERY_IDS)) == ("Identity Protection GraphQL:write",)


def test_the_registry_and_every_nested_value_resist_mutation() -> None:
    with pytest.raises(TypeError):
        OPERATIONS["GetQueriesAlertsV2"] = OPERATIONS["PostEntitiesAlertsV2"]  # type: ignore[index]
    descriptor = OPERATIONS["GetQueriesAlertsV2"]
    with pytest.raises(dataclasses.FrozenInstanceError):
        descriptor.path = "/entities/devices/action"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        descriptor.evidence.doc_scope = "Hosts: WRITE"  # type: ignore[misc]
    with pytest.raises(AttributeError):
        descriptor.scopes.append("Hosts:write")  # type: ignore[attr-defined]
    assert OPERATIONS["GetQueriesAlertsV2"].path == "/alerts/queries/alerts/v2"
    assert OPERATIONS["GetQueriesAlertsV2"].evidence.doc_scope == "Alerts: READ"
    assert OPERATIONS["GetQueriesAlertsV2"].scopes == ("Alerts:read",)


def test_an_unregistered_operation_id_fails_with_read_only_violation_before_anything_is_sent() -> None:
    with pytest.raises(CliError) as error:
        operation("PatchEntitiesAlertsV3")
    assert error.value.code == "READ_ONLY_VIOLATION"
    with pytest.raises(CliError):
        operation("get")
    # The one write-scoped neighbour falcon-mcp registers and captain exception N1 does not admit.
    with pytest.raises(CliError):
        operation("UploadLookupV1")


def test_the_second_enforcement_tier_admits_no_operation_beyond_captain_exception_n1() -> None:
    from falcon_axi.transport.operations import _seal

    admitted = OPERATIONS["StartSearchV1"]
    relabelled = dataclasses.replace(admitted, id="PostEntitiesAlertsV2")
    with pytest.raises(ValueError, match="captain exception N1"):
        _seal(relabelled)
    broadened = dataclasses.replace(admitted, scopes=("NGSIEM:write", "Hosts:write"))
    with pytest.raises(ValueError, match="captain exception N1"):
        _seal(broadened)
    smuggled = dataclasses.replace(
        OPERATIONS["PostEntitiesAlertsV2"],
        scopes=("Alerts:write",),
    )
    with pytest.raises(ValueError, match="declares a write scope"):
        _seal(smuggled)


def test_the_second_citation_is_falcon_mcp_or_falconpy_plus_psfalcon_and_nothing_weaker() -> None:
    from falcon_axi.transport.operations import Evidence, _seal

    base = OPERATIONS["query_accounts"]
    weaker = (
        "falcon-mcp has no tool for query_accounts.",
        "falcon-mcp has no tool for query_accounts. PSFalcon Get-FalconAsset -Account wraps it.",
        "falcon-mcp has no tool for query_accounts. falconpy/_endpoint/_discover.py maps query_accounts "
        "to GET /discover/queries/accounts/v1.",
        "falcon-mcp has no tool for query_accounts. falconpy/_endpoint/_discover.py maps query_accounts "
        "to GET /discover/queries/other/v1. PSFalcon Get-FalconAsset -Account wraps it.",
        "an unrelated note",
    )
    for citation in weaker:
        evidence = Evidence(base.evidence.doc_url, base.evidence.doc_scope, citation)
        with pytest.raises(ValueError, match="corroboration"):
            _seal(dataclasses.replace(base, evidence=evidence))

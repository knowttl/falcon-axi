"""The complete scoped-operation surface of falcon-axi v1 (docs/design/v1.md §2.1, §3.3).

The union is closed: adding a member requires both §2.2 citations in the same change.
When falcon-mcp has no tool for the operation, the second citation is falconpy's generated
endpoint table plus another first-party CrowdStrike SDK (PSFalcon), not a missing falcon-mcp row.

The read tier admits only read-scoped operations. Captain exceptions N1 and N2 admit the two
write-labelled effects defined below (docs/design/v1.md §4.3, §4.4); each is confined to its own
id allowlist and scope, and N2 additionally requires fixed read-only query documents.
N3 admits four exact read-scoped RTR lifecycle tuples, behind separate one-run authorization.
"""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal, get_args

from falcon_axi.core import CliError

OperationId = Literal[
    "QueryReports",
    "GetSummaryReports",
    "combined_summary_get",
    "combined_edges_get",
    "RTR_ListAllSessions",
    "RTR_ListSessions",
    "RTRAuditSessions",
    "RTR_InitSession",
    "RTR_ExecuteCommand",
    "RTR_CheckCommandStatus",
    "RTR_DeleteSession",
    "exclusions_search_v2",
    "exclusions_get_v2",
    "ss_ioa_exclusions_search_v2",
    "ss_ioa_exclusions_get_v2",
    "querySensorVisibilityExclusionsV1",
    "getSensorVisibilityExclusionsV1",
    "cb_exclusions_query_v1",
    "cb_exclusions_get_v1",
    "QueryQuarantineFiles",
    "GetQuarantineFiles",
    "cloud_security_assets_queries",
    "cloud_security_assets_entities_get",
    "cspm_evaluations_iom_queries",
    "cspm_evaluations_iom_entities",
    "combined_cloud_risks",
    "GetSensorUsageWeekly",
    "QueryRulesV1",
    "GetRulesV1",
    "QueryNotificationsV1",
    "GetNotificationsDetailedV1",
    "QueryNotificationsExposedDataRecordsV1",
    "GetNotificationsExposedDataRecordsV1",
    "GetSecurityChecksV3",
    "GetCombinedVulnerabilitiesSARIF",
    "ReadContainerCombined",
    "ReadCombinedVulnerabilities",
    "GetCombinedImages",
    "queries_classification_get_v2",
    "entities_classification_get_v2",
    "queries_policy_get_v2",
    "entities_policy_get_v2",
    "queryCombinedPreventionPolicies",
    "queryCombinedPreventionPolicyMembers",
    "queryCombinedSensorUpdatePoliciesV2",
    "queryCombinedSensorUpdatePolicyMembers",
    "queryCombinedFirewallPolicies",
    "queryCombinedFirewallPolicyMembers",
    "queryCombinedDeviceControlPolicies",
    "queryCombinedDeviceControlPolicyMembers",
    "queryCombinedRTResponsePolicies",
    "queryCombinedRTResponsePolicyMembers",
    "queryCombinedContentUpdatePolicies",
    "queryCombinedContentUpdatePolicyMembers",
    "indicator_search_v1",
    "indicator_get_v1",
    "DevicesRanOn",
    "ProcessesRanOn",
    "entities_processes",
    "queryCombinedHostGroups",
    "queryCombinedGroupMembers",
    "combined_hosts",
    "get_hosts",
    "combined_applications",
    "query_logins",
    "get_logins",
    "QueryGetNetworkAddressHistoryV1",
    "QuerySensorsByFilter",
    "GetSensorDetails",
    "QueryVulnerabilities",
    "getVulnerabilities",
    "GetQueriesAlertsV2",
    "PostEntitiesAlertsV2",
    "PostAggregatesAlertsV2",
    "QueryDevicesByFilter",
    "PostDeviceDetailsV2",
    "combinedQueryVulnerabilities",
    "GetVulnerabilities",
    "QueryIntelActorEntities",
    "GetIntelActorEntities",
    "QueryIntelReportEntities",
    "GetIntelReportEntities",
    "GetMitreReport",
    "QueryIntelIndicatorEntities",
    "GetIntelIndicatorEntities",
    "QueryDeviceLoginHistoryV2",
    "query_accounts",
    "get_accounts",
    "query_rules",
    "get_rules",
    "query_rule_groups",
    "get_rule_groups",
    "query_rule_groups_full",
    "combined_rules_get_v2",
    "queries_cases_get_v1",
    "entities_cases_post_v2",
    "StartSearchV1",
    "GetSearchStatusV1",
    "StopSearchV1",
    "api_preempt_proxy_post_graphql",
    "QueryMalwareEntities",
    "GetMalwareEntities",
    "get_policy_rules_query",
    "get_policy_rules",
    "query_iot_hostsV2",
    "get_iot_hosts",
]

OPERATION_IDS: tuple[str, ...] = get_args(OperationId)

Effect = Literal["read", "search-lifecycle", "graphql-query", "rtr-read-only-execute"]
EFFECTS: tuple[str, ...] = get_args(Effect)

RTR_EXECUTION_TUPLES = MappingProxyType(
    {
        "RTR_InitSession": (
            "POST",
            "/real-time-response/entities/sessions/v1",
            "rtr-read-only-execute",
            ("Real time response:read",),
        ),
        "RTR_ExecuteCommand": (
            "POST",
            "/real-time-response/entities/command/v1",
            "rtr-read-only-execute",
            ("Real time response:read",),
        ),
        "RTR_CheckCommandStatus": (
            "GET",
            "/real-time-response/entities/command/v1",
            "rtr-read-only-execute",
            ("Real time response:read",),
        ),
        "RTR_DeleteSession": (
            "DELETE",
            "/real-time-response/entities/sessions/v1",
            "rtr-read-only-execute",
            ("Real time response:read",),
        ),
    }
)
RTR_EXECUTION_IDS = frozenset(RTR_EXECUTION_TUPLES)

#: The whole of captain exception N1 (docs/design/v1.md §4.3): the only ids whose effect may be
#: `search-lifecycle`, and so the only ids that may cite a write scope. `GetSearchStatusV1` is not
#: a member because it is an ordinary `NGSIEM:read` read of a job falcon-axi already started.
SEARCH_LIFECYCLE_IDS: frozenset[str] = frozenset({"StartSearchV1", "StopSearchV1"})

#: The one write scope N1 admits; the N2 scope is confined to the separate GraphQL tier.
SEARCH_LIFECYCLE_SCOPES: tuple[str, ...] = ("NGSIEM:write",)


#: The whole of captain exception N2 (docs/design/v1.md §4.4): the only id whose effect may be
#: `graphql-query`. It is write-labelled because Falcon scopes the one Identity Protection GraphQL
#: endpoint `WRITE` even for a read-only query, and the same endpoint also accepts mutations.
#: falcon-axi therefore never sends caller-supplied GraphQL: only the fixed query documents in
#: `falcon_axi/transport/graphql.py` reach it.
GRAPHQL_QUERY_IDS: frozenset[str] = frozenset({"api_preempt_proxy_post_graphql"})

#: The one write-labelled scope N2 admits. The per-document `:read` scopes live with the documents.
GRAPHQL_QUERY_SCOPES: tuple[str, ...] = ("Identity Protection GraphQL:write",)


@dataclass(frozen=True)
class Evidence:
    doc_url: str
    doc_scope: str
    #: Second citation (§2.2). falcon-mcp when it has a tool; otherwise falconpy's generated
    #: endpoint table plus PSFalcon. The field name is the historical citation.
    falcon_mcp: str


@dataclass(frozen=True)
class FalconOperation:
    id: OperationId
    method: Literal["GET", "POST", "DELETE"]
    path: str
    scopes: tuple[str, ...]
    effect: Effect
    evidence: Evidence


ALERTS_DOC = "https://developer.crowdstrike.com/api-reference/collections/alerts/"
HOSTS_DOC = "https://developer.crowdstrike.com/api-reference/collections/hosts/"
SPOTLIGHT_DOC = "https://developer.crowdstrike.com/api-reference/collections/spotlight-vulnerabilities/"
INTEL_DOC = "https://developer.crowdstrike.com/api-reference/collections/intel/"
DISCOVER_DOC = "https://developer.crowdstrike.com/api-reference/collections/discover/"
NGSIEM_DOC = "https://developer.crowdstrike.com/api-reference/collections/ngsiem/"
IDENTITY_PROTECTION_DOC = "https://developer.crowdstrike.com/api-reference/collections/identity-protection/"

CANONICAL: tuple[FalconOperation, ...] = (
    FalconOperation(
        id="combined_summary_get",
        method="GET",
        path="/threatgraph/combined/{vertex_type}/summary/v1",
        scopes=("Threatgraph:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/threatgraph/#combined_summary_get",
            doc_scope="Threatgraph: READ",
            falcon_mcp=(
                "falcon-mcp has no tool for combined_summary_get. "
                "falconpy/_endpoint/_threatgraph.py maps combined_summary_get to GET "
                "/threatgraph/combined/{vertex_type}/summary/v1 (the SDK table uses {} with vertex_type). "
                "PSFalcon Get-FalconThreatGraphVertex -IncludeEdge wraps the same operation."
            ),
        ),
    ),
    FalconOperation(
        id="combined_edges_get",
        method="GET",
        path="/threatgraph/combined/edges/v1",
        scopes=("Threatgraph:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/threatgraph/#combined_edges_get",
            doc_scope="Threatgraph: READ",
            falcon_mcp=(
                "falcon-mcp has no tool for combined_edges_get. "
                "falconpy/_endpoint/_threatgraph.py maps combined_edges_get to GET "
                "/threatgraph/combined/edges/v1. PSFalcon Get-FalconThreatGraphEdge wraps the same operation."
            ),
        ),
    ),
    FalconOperation(
        id="RTR_ListAllSessions",
        method="GET",
        path="/real-time-response/queries/sessions/v1",
        scopes=("Real time response:read",),
        effect="read",
        evidence=Evidence(
            "https://developer.crowdstrike.com/api-reference/collections/real-time-response/#rtr-listallsessions",
            "Real time response: READ",
            "falcon_mcp/common/api_scopes.py maps RTR_ListAllSessions to Real time response:read; "
            "falcon_mcp/modules/rtr.py search_sessions queries this id before hydration.",
        ),
    ),
    FalconOperation(
        id="RTR_ListSessions",
        method="POST",
        path="/real-time-response/entities/sessions/GET/v1",
        scopes=("Real time response:read",),
        effect="read",
        evidence=Evidence(
            "https://developer.crowdstrike.com/api-reference/collections/real-time-response/#rtr-listsessions",
            "Real time response: READ",
            "falcon_mcp/common/api_scopes.py maps RTR_ListSessions to Real time response:read; "
            "falcon_mcp/modules/rtr.py search_sessions hydrates ids in a POST body and restores query order.",
        ),
    ),
    FalconOperation(
        id="RTRAuditSessions",
        method="GET",
        path="/real-time-response-audit/combined/sessions/v1",
        scopes=("Real time response audit:read",),
        effect="read",
        evidence=Evidence(
            "https://developer.crowdstrike.com/api-reference/collections/real-time-response-audit/#rtrauditsessions",
            "Real time response audit: READ",
            "falcon_mcp/common/api_scopes.py maps RTRAuditSessions to real-time-response-audit:read "
            "(Real time response audit:read); falcon_mcp/modules/rtr.py search_audit_sessions reads combined records.",
        ),
    ),
    FalconOperation(
        "RTR_InitSession",
        "POST",
        "/real-time-response/entities/sessions/v1",
        ("Real time response:read",),
        "rtr-read-only-execute",
        Evidence(
            "https://developer.crowdstrike.com/api-reference/collections/real-time-response/#rtr-initsession",
            "Real time response: READ",
            "falcon_mcp/common/api_scopes.py maps RTR_InitSession to Real time response:read; "
            "falcon_mcp/modules/rtr.py init_session uses RTR_InitSession.",
        ),
    ),
    FalconOperation(
        "RTR_ExecuteCommand",
        "POST",
        "/real-time-response/entities/command/v1",
        ("Real time response:read",),
        "rtr-read-only-execute",
        Evidence(
            "https://developer.crowdstrike.com/api-reference/collections/real-time-response/#rtr-executecommand",
            "Real time response: READ",
            "falcon_mcp/common/api_scopes.py maps RTR_ExecuteCommand to Real time response:read; "
            "falcon_mcp/modules/rtr.py execute_read_only_command uses RTR_ExecuteCommand.",
        ),
    ),
    FalconOperation(
        "RTR_CheckCommandStatus",
        "GET",
        "/real-time-response/entities/command/v1",
        ("Real time response:read",),
        "rtr-read-only-execute",
        Evidence(
            "https://developer.crowdstrike.com/api-reference/collections/real-time-response/#rtr-checkcommandstatus",
            "Real time response: READ",
            "falcon_mcp/common/api_scopes.py maps RTR_CheckCommandStatus to Real time response:read; "
            "falcon_mcp/modules/rtr.py check_command_status uses RTR_CheckCommandStatus.",
        ),
    ),
    FalconOperation(
        "RTR_DeleteSession",
        "DELETE",
        "/real-time-response/entities/sessions/v1",
        ("Real time response:read",),
        "rtr-read-only-execute",
        Evidence(
            "https://developer.crowdstrike.com/api-reference/collections/real-time-response/#rtr-deletesession",
            "Real time response: READ",
            "falcon_mcp/common/api_scopes.py maps RTR_DeleteSession to Real time response:read; "
            "falcon_mcp/modules/rtr.py delete_session uses RTR_DeleteSession.",
        ),
    ),
    FalconOperation(
        id="QueryMalwareEntities",
        method="GET",
        path="/intel/combined/malware/v1",
        scopes=("Malware Families (Falcon Intelligence):read",),
        effect="read",
        evidence=Evidence(
            INTEL_DOC,
            "Malware Families (Falcon Intelligence): READ",
            "falcon-mcp has no tool for QueryMalwareEntities. "
            "falconpy/_endpoint/_intel.py maps QueryMalwareEntities to GET /intel/combined/malware/v1. "
            "PSFalcon public/intel.ps1 Get-FalconMalwareFamily -Detailed wraps it.",
        ),
    ),
    FalconOperation(
        id="QueryReports",
        method="GET",
        path="/falconx/queries/reports/v1",
        scopes=("Sandbox (Falcon Intelligence):read",),
        effect="read",
        evidence=Evidence(
            "https://developer.crowdstrike.com/api-reference/collections/falconx-sandbox/#queryreports",
            "Sandbox (Falcon Intelligence): READ",
            "falcon-mcp has no tool for QueryReports. "
            "falconpy/_endpoint/_falconx_sandbox.py maps QueryReports to GET /falconx/queries/reports/v1. "
            "PSFalcon public/falconx.ps1 Get-FalconReport's default parameter set wraps QueryReports.",
        ),
    ),
    FalconOperation(
        id="GetSummaryReports",
        method="GET",
        path="/falconx/entities/report-summaries/v1",
        scopes=("Sandbox (Falcon Intelligence):read",),
        effect="read",
        evidence=Evidence(
            "https://developer.crowdstrike.com/api-reference/collections/falconx-sandbox/#getsummaryreports",
            "Sandbox (Falcon Intelligence): READ",
            "falcon-mcp has no tool for GetSummaryReports. "
            "falconpy/_endpoint/_falconx_sandbox.py maps GetSummaryReports to GET /falconx/entities/report-summaries/v1. "
            "PSFalcon public/falconx.ps1 Get-FalconReport -Summary wraps GetSummaryReports.",
        ),
    ),
    FalconOperation(
        id="GetMalwareEntities",
        method="GET",
        path="/intel/entities/malware/v1",
        scopes=("Malware Families (Falcon Intelligence):read",),
        effect="read",
        evidence=Evidence(
            INTEL_DOC,
            "Malware Families (Falcon Intelligence): READ",
            "falcon-mcp has no tool for GetMalwareEntities. "
            "falconpy/_endpoint/_intel.py maps GetMalwareEntities to GET /intel/entities/malware/v1. "
            "PSFalcon public/intel.ps1 Get-FalconMalwareFamily -Id wraps it.",
        ),
    ),
    FalconOperation(
        id="get_policy_rules_query",
        method="GET",
        path="/identity-protection/queries/policy-rules/v1",
        scopes=("Identity Protection Policy Rules:read",),
        effect="read",
        evidence=Evidence(
            IDENTITY_PROTECTION_DOC,
            "Identity Protection Policy Rules: READ",
            "falcon-mcp has no tool for get_policy_rules_query. "
            "falconpy/_endpoint/_identity_protection.py maps get_policy_rules_query to GET "
            "/identity-protection/queries/policy-rules/v1. "
            "PSFalcon public/identity-protection.ps1 Get-FalconIdentityRule wraps it.",
        ),
    ),
    FalconOperation(
        id="get_policy_rules",
        method="GET",
        path="/identity-protection/entities/policy-rules/v1",
        scopes=("Identity Protection Policy Rules:read",),
        effect="read",
        evidence=Evidence(
            IDENTITY_PROTECTION_DOC,
            "Identity Protection Policy Rules: READ",
            "falcon-mcp has no tool for get_policy_rules. "
            "falconpy/_endpoint/_identity_protection.py maps get_policy_rules to GET "
            "/identity-protection/entities/policy-rules/v1. "
            "PSFalcon public/identity-protection.ps1 Get-FalconIdentityRule -Id wraps it.",
        ),
    ),
    FalconOperation(
        id="query_iot_hostsV2",
        method="GET",
        path="/discover/queries/iot-hosts/v2",
        scopes=("Falcon Discover IoT:read",),
        effect="read",
        evidence=Evidence(
            DISCOVER_DOC,
            "Falcon Discover IoT: READ",
            "falcon-mcp has no tool for query_iot_hostsV2. "
            "falconpy/_endpoint/_discover.py maps query_iot_hostsV2 to GET /discover/queries/iot-hosts/v2. "
            "PSFalcon public/discover.ps1 Get-FalconAsset -IoT wraps it.",
        ),
    ),
    FalconOperation(
        id="get_iot_hosts",
        method="GET",
        path="/discover/entities/iot-hosts/v1",
        scopes=("Falcon Discover IoT:read",),
        effect="read",
        evidence=Evidence(
            DISCOVER_DOC,
            "Falcon Discover IoT: READ",
            "falcon-mcp has no tool for get_iot_hosts. "
            "falconpy/_endpoint/_discover.py maps get_iot_hosts to GET /discover/entities/iot-hosts/v1. "
            "PSFalcon public/discover.ps1 Get-FalconAsset -IoT -Id wraps it.",
        ),
    ),
    FalconOperation(
        id="query_rules",
        method="GET",
        path="/fwmgr/queries/rules/v1",
        scopes=("Firewall Management:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/firewall-management/#query-rules",
            doc_scope="Firewall management: READ",
            falcon_mcp="falcon_mcp/common/api_scopes.py maps query_rules to Firewall Management:read; "
            "falcon_mcp/modules/firewall.py search_firewall_rules uses query_rules then get_rules; "
            "falconpy/_endpoint/_firewall_management.py confirms the route and parameters.",
        ),
    ),
    FalconOperation(
        id="get_rules",
        method="GET",
        path="/fwmgr/entities/rules/v1",
        scopes=("Firewall Management:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/firewall-management/#get-rules",
            doc_scope="Firewall management: READ",
            falcon_mcp="falcon_mcp/common/api_scopes.py maps get_rules to Firewall Management:read; "
            "falcon_mcp/modules/firewall.py search_firewall_rules hydrates ids as query parameters; "
            "falconpy/_endpoint/_firewall_management.py confirms the route and parameters.",
        ),
    ),
    FalconOperation(
        id="query_rule_groups",
        method="GET",
        path="/fwmgr/queries/rule-groups/v1",
        scopes=("Firewall Management:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/firewall-management/#query-rule-groups",
            doc_scope="Firewall management: READ",
            falcon_mcp="falcon_mcp/common/api_scopes.py maps query_rule_groups to Firewall Management:read; "
            "falcon_mcp/modules/firewall.py search_firewall_rule_groups uses after pagination; "
            "falconpy/_endpoint/_firewall_management.py confirms the route and parameters.",
        ),
    ),
    FalconOperation(
        id="get_rule_groups",
        method="GET",
        path="/fwmgr/entities/rule-groups/v1",
        scopes=("Firewall Management:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/firewall-management/#get-rule-groups",
            doc_scope="Firewall management: READ",
            falcon_mcp="falcon_mcp/common/api_scopes.py maps get_rule_groups to Firewall Management:read; "
            "falcon_mcp/modules/firewall.py search_firewall_rule_groups hydrates ids as query parameters; "
            "falconpy/_endpoint/_firewall_management.py confirms the route and parameters.",
        ),
    ),
    FalconOperation(
        id="query_rule_groups_full",
        method="GET",
        path="/ioarules/queries/rule-groups-full/v1",
        scopes=("Custom IOA Rules:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/custom-ioa/#query-rule-groups-full",
            doc_scope="Custom IOA rules: READ",
            falcon_mcp="falcon_mcp/common/api_scopes.py maps query_rule_groups_full to Custom IOA Rules:read; "
            "falcon_mcp/modules/custom_ioa.py search_ioa_rule_groups reads full groups with offset pagination; "
            "falconpy/_endpoint/_custom_ioa.py confirms the route and parameters.",
        ),
    ),
    FalconOperation(
        id="combined_rules_get_v2",
        method="GET",
        path="/correlation-rules/combined/rules/v2",
        scopes=("Correlation Rules:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/correlation-rules/#combinedrulesgetv2",
            doc_scope="Correlation Rules: READ",
            falcon_mcp="falcon_mcp/common/api_scopes.py maps combined_rules_get_v2 to Correlation Rules:read; "
            "falcon_mcp/modules/correlation_rules.py search_correlation_rules reads full rules with offset pagination; "
            "falconpy/_endpoint/_correlation_rules.py confirms the route and parameters.",
        ),
    ),
    FalconOperation(
        id="queries_cases_get_v1",
        method="GET",
        path="/cases/queries/cases/v1",
        scopes=("Cases:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/case-management/#queriescasesgetv1",
            doc_scope="Cases: READ",
            falcon_mcp="falcon_mcp/common/api_scopes.py maps queries_cases_get_v1 to Cases:read; "
            "falcon_mcp/modules/cases.py search_cases queries ids then hydrates them, preserving query order; "
            "falconpy/_endpoint/_case_management.py confirms the route and parameters.",
        ),
    ),
    FalconOperation(
        id="entities_cases_post_v2",
        method="POST",
        path="/cases/entities/cases/v2",
        scopes=("Cases:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/case-management/#entitiescasespostv2",
            doc_scope="Cases: READ",
            falcon_mcp="falcon_mcp/common/api_scopes.py maps entities_cases_post_v2 to Cases:read; "
            "falcon_mcp/modules/cases.py get_cases reads ids in the request body; "
            "falconpy/_endpoint/_case_management.py confirms the route and parameters.",
        ),
    ),
    FalconOperation(
        id="exclusions_search_v2",
        method="GET",
        path="/exclusions/queries/exclusions/v2",
        scopes=("Machine Learning Exclusions:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/ml-exclusions/",
            doc_scope="Machine Learning Exclusions: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps exclusions_search_v2 to Machine Learning Exclusions:read; "
                "falcon_mcp/modules/exclusions.py uses it for search_exclusions."
            ),
        ),
    ),
    FalconOperation(
        id="exclusions_get_v2",
        method="GET",
        path="/exclusions/entities/exclusions/v2",
        scopes=("Machine Learning Exclusions:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/ml-exclusions/",
            doc_scope="Machine Learning Exclusions: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps exclusions_get_v2 to Machine Learning Exclusions:read; "
                "falcon_mcp/modules/exclusions.py uses it for search_exclusions."
            ),
        ),
    ),
    FalconOperation(
        id="ss_ioa_exclusions_search_v2",
        method="GET",
        path="/exclusions/queries/ss-ioa-exclusions/v2",
        scopes=("IOA Exclusions:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/ioa-exclusions/",
            doc_scope="IOA Exclusions: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps ss_ioa_exclusions_search_v2 to IOA Exclusions:read; "
                "falcon_mcp/modules/exclusions.py uses it for search_exclusions."
            ),
        ),
    ),
    FalconOperation(
        id="ss_ioa_exclusions_get_v2",
        method="GET",
        path="/exclusions/entities/ss-ioa-exclusions/v2",
        scopes=("IOA Exclusions:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/ioa-exclusions/",
            doc_scope="IOA Exclusions: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps ss_ioa_exclusions_get_v2 to IOA Exclusions:read; "
                "falcon_mcp/modules/exclusions.py uses it for search_exclusions."
            ),
        ),
    ),
    FalconOperation(
        id="querySensorVisibilityExclusionsV1",
        method="GET",
        path="/policy/queries/sv-exclusions/v1",
        scopes=("Sensor Visibility Exclusions:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/sensor-visibility-exclusions/",
            doc_scope="Sensor Visibility Exclusions: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps querySensorVisibilityExclusionsV1 to Sensor Visibility Exclusions:read; "
                "falcon_mcp/modules/exclusions.py uses it for search_exclusions."
            ),
        ),
    ),
    FalconOperation(
        id="getSensorVisibilityExclusionsV1",
        method="GET",
        path="/policy/entities/sv-exclusions/v1",
        scopes=("Sensor Visibility Exclusions:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/sensor-visibility-exclusions/",
            doc_scope="Sensor Visibility Exclusions: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps getSensorVisibilityExclusionsV1 to Sensor Visibility Exclusions:read; "
                "falcon_mcp/modules/exclusions.py uses it for search_exclusions."
            ),
        ),
    ),
    FalconOperation(
        id="cb_exclusions_query_v1",
        method="GET",
        path="/exclusions/queries/cert-based-exclusions/v1",
        scopes=("Machine Learning Exclusions:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/certificate-based-exclusions/",
            doc_scope="Machine Learning Exclusions: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps cb_exclusions_query_v1 to Machine Learning Exclusions:read; "
                "falcon_mcp/modules/exclusions.py uses it for search_exclusions."
            ),
        ),
    ),
    FalconOperation(
        id="cb_exclusions_get_v1",
        method="GET",
        path="/exclusions/entities/cert-based-exclusions/v1",
        scopes=("Machine Learning Exclusions:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/certificate-based-exclusions/",
            doc_scope="Machine Learning Exclusions: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps cb_exclusions_get_v1 to Machine Learning Exclusions:read; "
                "falcon_mcp/modules/exclusions.py uses it for search_exclusions."
            ),
        ),
    ),
    FalconOperation(
        id="QueryQuarantineFiles",
        method="GET",
        path="/quarantine/queries/quarantined-files/v1",
        scopes=("Quarantined Files:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/quarantine/",
            doc_scope="Quarantined Files: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps QueryQuarantineFiles to Quarantined Files:read; "
                "falcon_mcp/modules/quarantine.py uses it for search_quarantined_files."
            ),
        ),
    ),
    FalconOperation(
        id="GetQuarantineFiles",
        method="POST",
        path="/quarantine/entities/quarantined-files/GET/v1",
        scopes=("Quarantined Files:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/quarantine/",
            doc_scope="Quarantined Files: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps GetQuarantineFiles to Quarantined Files:read; "
                "falcon_mcp/modules/quarantine.py uses it for search_quarantined_files."
            ),
        ),
    ),
    FalconOperation(
        id="GetSensorUsageWeekly",
        method="GET",
        path="/billing-dashboards-usage/aggregates/weekly-average/v1",
        scopes=("Sensor Usage:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/sensor-usage/",
            doc_scope="Sensor Usage: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps GetSensorUsageWeekly to Sensor Usage:read; "
                "falcon_mcp/modules/sensor_usage.py search_sensor_usage passes filter only. "
                "falconpy/_endpoint/_sensor_usage.py corroborates the route and parameter."
            ),
        ),
    ),
    FalconOperation(
        id="queries_classification_get_v2",
        method="GET",
        path="/data-protection/queries/classifications/v2",
        scopes=("Data Protection:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/data-protection-configuration/#queriesclassificationgetv2",
            doc_scope="Data Protection: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps queries_classification_get_v2 to Data Protection:read; "
                "falcon_mcp/modules/data_security.py _OPERATIONS and search_data_security_entities query then hydrate. "
                "https://github.com/CrowdStrike/falcon-mcp/blob/ece8575/falcon_mcp/modules/data_security.py; "
                "falconpy/_endpoint/_data_protection_configuration.py confirms GET, filter, sort, "
                "limit <=500 and offset <=10000."
            ),
        ),
    ),
    FalconOperation(
        id="GetCombinedVulnerabilitiesSARIF",
        method="GET",
        path="/lambdas/combined/vulnerabilities/sarif/v1",
        scopes=("Falcon Container Image:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/serverless-vulnerabilities/",
            doc_scope="Falcon Container Image: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps GetCombinedVulnerabilitiesSARIF to Falcon Container Image:read; "
                "falcon-mcp ece8575 falcon_mcp/modules/serverless.py search_serverless_vulnerabilities "
                "uses filter, limit, offset, sort and body.runs SARIF. "
                "falconpy/_endpoint/_serverless_vulnerabilities.py confirms GET /lambdas/combined/vulnerabilities/sarif/v1."
            ),
        ),
    ),
    FalconOperation(
        id="entities_classification_get_v2",
        method="GET",
        path="/data-protection/entities/classifications/v2",
        scopes=("Data Protection:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/data-protection-configuration/#entitiesclassificationgetv2",
            doc_scope="Data Protection: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps entities_classification_get_v2 to Data Protection:read; "
                "falcon_mcp/modules/data_security.py get_data_security_entities sends ids as query parameters. "
                "https://github.com/CrowdStrike/falcon-mcp/blob/ece8575/falcon_mcp/modules/data_security.py; "
                "falconpy/_endpoint/_data_protection_configuration.py confirms GET and at most 100 ids."
            ),
        ),
    ),
    FalconOperation(
        id="QueryRulesV1",
        method="GET",
        path="/recon/queries/rules/v1",
        scopes=("Monitoring rules (Falcon Intelligence Recon):read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/recon/",
            doc_scope="Monitoring rules (Falcon Intelligence Recon): READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps QueryRulesV1 to Monitoring rules (Falcon Intelligence Recon):read; "
                "falcon_mcp/modules/recon.py search_recon_rules queries ids with filter, limit and offset. "
                "falconpy/_endpoint/_recon.py corroborates the route and parameters."
            ),
        ),
    ),
    FalconOperation(
        id="queries_policy_get_v2",
        method="GET",
        path="/data-protection/queries/policies/v2",
        scopes=("Data Protection:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/data-protection-configuration/#queriespolicygetv2",
            doc_scope="Data Protection: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps queries_policy_get_v2 to Data Protection:read; "
                "falcon_mcp/modules/data_security.py search_data_security_entities requires "
                "platform_name win or mac for policy. "
                "https://github.com/CrowdStrike/falcon-mcp/blob/ece8575/falcon_mcp/modules/data_security.py; "
                "falconpy/_endpoint/_data_protection_configuration.py confirms GET, filter, sort, "
                "limit <=500 and offset <=10000."
            ),
        ),
    ),
    FalconOperation(
        id="ReadContainerCombined",
        method="GET",
        path="/container-security/combined/containers/v1",
        scopes=("Falcon Container Image:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/kubernetes-protection/",
            doc_scope="Falcon Container Image: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps ReadContainerCombined to Falcon Container Image:read; "
                "falcon-mcp ece8575 falcon_mcp/modules/cloud/cloud_containers.py search_kubernetes_containers "
                "uses filter, limit, offset, sort and resources with meta.pagination. "
                "falconpy/_endpoint/_kubernetes_protection.py confirms the 200 page cap and 10000 window."
            ),
        ),
    ),
    FalconOperation(
        id="GetRulesV1",
        method="GET",
        path="/recon/entities/rules/v1",
        scopes=("Monitoring rules (Falcon Intelligence Recon):read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/recon/",
            doc_scope="Monitoring rules (Falcon Intelligence Recon): READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps GetRulesV1 to Monitoring rules (Falcon Intelligence Recon):read; "
                "falcon_mcp/modules/recon.py search_recon_rules hydrates query ids with query parameters. "
                "falconpy/_endpoint/_recon.py corroborates the route and ids parameter."
            ),
        ),
    ),
    FalconOperation(
        id="ReadCombinedVulnerabilities",
        method="GET",
        path="/container-security/combined/vulnerabilities/v1",
        scopes=("Falcon Container Image:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/container-vulnerabilities/",
            doc_scope="Falcon Container Image: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps ReadCombinedVulnerabilities to Falcon Container Image:read; "
                "falcon-mcp ece8575 falcon_mcp/modules/cloud/cloud_containers.py search_images_vulnerabilities "
                "uses filter, limit, offset, sort and resources with meta.pagination. "
                "falconpy/_endpoint/_container_vulnerabilities.py confirms the 100 page cap and 10000 window."
            ),
        ),
    ),
    FalconOperation(
        id="QueryNotificationsV1",
        method="GET",
        path="/recon/queries/notifications/v1",
        scopes=("Monitoring rules (Falcon Intelligence Recon):read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/recon/",
            doc_scope="Monitoring rules (Falcon Intelligence Recon): READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps QueryNotificationsV1 to Monitoring rules "
                "(Falcon Intelligence Recon):read; falcon_mcp/modules/recon.py search_recon_notifications "
                "queries ids with filter, limit and offset. falconpy/_endpoint/_recon.py corroborates the parameters."
            ),
        ),
    ),
    FalconOperation(
        id="GetNotificationsDetailedV1",
        method="GET",
        path="/recon/entities/notifications-detailed/v1",
        scopes=("Monitoring rules (Falcon Intelligence Recon):read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/recon/",
            doc_scope="Monitoring rules (Falcon Intelligence Recon): READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps GetNotificationsDetailedV1 to Monitoring rules "
                "(Falcon Intelligence Recon):read; falcon_mcp/modules/recon.py search_recon_notifications "
                "hydrates ids and reads fields from nested notification. falconpy/_endpoint/_recon.py corroborates ids."
            ),
        ),
    ),
    FalconOperation(
        id="QueryNotificationsExposedDataRecordsV1",
        method="GET",
        path="/recon/queries/notifications-exposed-data-records/v1",
        scopes=("Monitoring rules (Falcon Intelligence Recon):read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/recon/",
            doc_scope="Monitoring rules (Falcon Intelligence Recon): READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps QueryNotificationsExposedDataRecordsV1 to Monitoring rules "
                "(Falcon Intelligence Recon):read; falcon_mcp/modules/recon.py search_recon_exposed_data_records "
                "queries ids with filter, limit and offset. falconpy/_endpoint/_recon.py corroborates the parameters."
            ),
        ),
    ),
    FalconOperation(
        id="GetNotificationsExposedDataRecordsV1",
        method="GET",
        path="/recon/entities/notifications-exposed-data-records/v1",
        scopes=("Monitoring rules (Falcon Intelligence Recon):read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/recon/",
            doc_scope="Monitoring rules (Falcon Intelligence Recon): READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps GetNotificationsExposedDataRecordsV1 to Monitoring rules "
                "(Falcon Intelligence Recon):read; falcon_mcp/modules/recon.py search_recon_exposed_data_records "
                "hydrates ids with query parameters. falconpy/_endpoint/_recon.py corroborates the route and ids."
            ),
        ),
    ),
    FalconOperation(
        id="GetSecurityChecksV3",
        method="GET",
        path="/saas-security/entities/checks/v3",
        scopes=("SaaS Security:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/saas-security/#getsecuritychecksv3",
            doc_scope="SaaS Security (Falcon Shield): READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps GetSecurityChecksV3 to SaaS Security:read; "
                "https://github.com/CrowdStrike/falcon-mcp/blob/main/falcon_mcp/modules/shield.py "
                "search_shield_checks sends id, status, impact, limit and offset; "
                "falconpy/_endpoint/_saas_security.py maps GetSecurityChecksV3 to "
                "GET /saas-security/entities/checks/v3"
            ),
        ),
    ),
    FalconOperation(
        id="GetCombinedImages",
        method="GET",
        path="/container-security/combined/image-assessment/images/v1",
        scopes=("Falcon Container Image:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/container-images/",
            doc_scope="Falcon Container Image: READ",
            falcon_mcp=(
                "falcon-mcp has no tool for GetCombinedImages. "
                "falconpy/_endpoint/_container_images.py maps GetCombinedImages to GET "
                "/container-security/combined/image-assessment/images/v1. "
                "PSFalcon b5f3774 public/container-security.ps1 Get-FalconContainerAssessment wraps "
                "the same filter, sort, limit and offset read."
            ),
        ),
    ),
    FalconOperation(
        id="entities_policy_get_v2",
        method="GET",
        path="/data-protection/entities/policies/v2",
        scopes=("Data Protection:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/data-protection-configuration/#entitiespolicygetv2",
            doc_scope="Data Protection: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps entities_policy_get_v2 to Data Protection:read; "
                "falcon_mcp/modules/data_security.py get_data_security_entities sends ids without platform_name. "
                "https://github.com/CrowdStrike/falcon-mcp/blob/ece8575/falcon_mcp/modules/data_security.py; "
                "falconpy/_endpoint/_data_protection_configuration.py confirms GET and at most 100 ids."
            ),
        ),
    ),
    FalconOperation(
        id="queryCombinedPreventionPolicies",
        method="GET",
        path="/policy/combined/prevention/v1",
        scopes=("Prevention Policies:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/prevention-policy/",
            doc_scope="Prevention Policies: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps queryCombinedPreventionPolicies "
                "to Prevention Policies:read; falcon_mcp/modules/policies.py _OPERATIONS "
                "and falconpy/_endpoint/_prevention_policies.py corroborate the combined read."
            ),
        ),
    ),
    FalconOperation(
        id="queryCombinedPreventionPolicyMembers",
        method="GET",
        path="/policy/combined/prevention-members/v1",
        scopes=("Prevention Policies:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/prevention-policy/",
            doc_scope="Prevention Policies: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps queryCombinedPreventionPolicyMembers "
                "to Prevention Policies:read; falcon_mcp/modules/policies.py _OPERATIONS "
                "and falconpy/_endpoint/_prevention_policies.py corroborate the combined read."
            ),
        ),
    ),
    FalconOperation(
        id="queryCombinedSensorUpdatePoliciesV2",
        method="GET",
        path="/policy/combined/sensor-update/v2",
        scopes=("Sensor Update Policies:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/sensor-update-policy/",
            doc_scope="Sensor Update Policies: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps queryCombinedSensorUpdatePoliciesV2 "
                "to Sensor Update Policies:read; falcon_mcp/modules/policies.py _OPERATIONS "
                "and falconpy/_endpoint/_sensor_update_policies.py corroborate the combined read."
            ),
        ),
    ),
    FalconOperation(
        id="queryCombinedSensorUpdatePolicyMembers",
        method="GET",
        path="/policy/combined/sensor-update-members/v1",
        scopes=("Sensor Update Policies:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/sensor-update-policy/",
            doc_scope="Sensor Update Policies: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps queryCombinedSensorUpdatePolicyMembers "
                "to Sensor Update Policies:read; falcon_mcp/modules/policies.py _OPERATIONS "
                "and falconpy/_endpoint/_sensor_update_policies.py corroborate the combined read."
            ),
        ),
    ),
    FalconOperation(
        id="queryCombinedFirewallPolicies",
        method="GET",
        path="/policy/combined/firewall/v1",
        scopes=("Firewall Management:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/firewall-policies/",
            doc_scope="Firewall Management: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps queryCombinedFirewallPolicies "
                "to Firewall Management:read; falcon_mcp/modules/policies.py _OPERATIONS "
                "and falconpy/_endpoint/_firewall_policies.py corroborate the combined read."
            ),
        ),
    ),
    FalconOperation(
        id="queryCombinedFirewallPolicyMembers",
        method="GET",
        path="/policy/combined/firewall-members/v1",
        scopes=("Firewall Management:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/firewall-policies/",
            doc_scope="Firewall Management: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps queryCombinedFirewallPolicyMembers "
                "to Firewall Management:read; falcon_mcp/modules/policies.py _OPERATIONS "
                "and falconpy/_endpoint/_firewall_policies.py corroborate the combined read."
            ),
        ),
    ),
    FalconOperation(
        id="queryCombinedDeviceControlPolicies",
        method="GET",
        path="/policy/combined/device-control/v1",
        scopes=("Device Control Policies:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/device-control-policies/",
            doc_scope="Device Control Policies: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps queryCombinedDeviceControlPolicies "
                "to Device Control Policies:read; falcon_mcp/modules/policies.py _OPERATIONS "
                "and falconpy/_endpoint/_device_control_policies.py corroborate the combined read."
            ),
        ),
    ),
    FalconOperation(
        id="queryCombinedDeviceControlPolicyMembers",
        method="GET",
        path="/policy/combined/device-control-members/v1",
        scopes=("Device Control Policies:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/device-control-policies/",
            doc_scope="Device Control Policies: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps queryCombinedDeviceControlPolicyMembers "
                "to Device Control Policies:read; falcon_mcp/modules/policies.py _OPERATIONS "
                "and falconpy/_endpoint/_device_control_policies.py corroborate the combined read."
            ),
        ),
    ),
    FalconOperation(
        id="queryCombinedRTResponsePolicies",
        method="GET",
        path="/policy/combined/response/v1",
        scopes=("Response Policies:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/response-policies/",
            doc_scope="Response Policies: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps queryCombinedRTResponsePolicies "
                "to Response Policies:read; falcon_mcp/modules/policies.py _OPERATIONS "
                "and falconpy/_endpoint/_response_policies.py corroborate the combined read."
            ),
        ),
    ),
    FalconOperation(
        id="queryCombinedRTResponsePolicyMembers",
        method="GET",
        path="/policy/combined/response-members/v1",
        scopes=("Response Policies:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/response-policies/",
            doc_scope="Response Policies: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps queryCombinedRTResponsePolicyMembers "
                "to Response Policies:read; falcon_mcp/modules/policies.py _OPERATIONS "
                "and falconpy/_endpoint/_response_policies.py corroborate the combined read."
            ),
        ),
    ),
    FalconOperation(
        id="queryCombinedContentUpdatePolicies",
        method="GET",
        path="/policy/combined/content-update/v1",
        scopes=("Content Update Policies:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/content-update-policies/",
            doc_scope="Content Update Policy: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps queryCombinedContentUpdatePolicies "
                "to Content Update Policies:read; falcon_mcp/modules/policies.py _OPERATIONS "
                "and falconpy/_endpoint/_content_update_policies.py corroborate the combined read."
            ),
        ),
    ),
    FalconOperation(
        id="queryCombinedContentUpdatePolicyMembers",
        method="GET",
        path="/policy/combined/content-update-members/v1",
        scopes=("Content Update Policies:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/content-update-policies/",
            doc_scope="Content Update Policy: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps queryCombinedContentUpdatePolicyMembers "
                "to Content Update Policies:read; falcon_mcp/modules/policies.py _OPERATIONS "
                "and falconpy/_endpoint/_content_update_policies.py corroborate the combined read."
            ),
        ),
    ),
    FalconOperation(
        id="indicator_search_v1",
        method="GET",
        path="/iocs/queries/indicators/v1",
        scopes=("IOC Management:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/ioc/#indicatorsearchv1",
            doc_scope="IOC Management: READ",
            falcon_mcp="falcon_mcp/common/api_scopes.py maps indicator_search_v1 to IOC Management:read; "
            "falcon_mcp/modules/ioc.py search_iocs uses after pagination and then indicator_get_v1",
        ),
    ),
    FalconOperation(
        id="indicator_get_v1",
        method="GET",
        path="/iocs/entities/indicators/v1",
        scopes=("IOC Management:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/ioc/#indicatorgetv1",
            doc_scope="IOC Management: READ",
            falcon_mcp="falcon_mcp/common/api_scopes.py maps indicator_get_v1 to IOC Management:read; "
            "falcon_mcp/modules/ioc.py search_iocs hydrates ids and restores query order",
        ),
    ),
    FalconOperation(
        id="DevicesRanOn",
        method="GET",
        path="/indicators/queries/devices/v1",
        scopes=("IOCs (Indicators of Compromise):read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/iocs/#devicesranon",
            doc_scope="IOCs (Indicators of Compromise): READ",
            falcon_mcp="falcon-mcp has no tool for DevicesRanOn. "
            "falconpy/_endpoint/_iocs.py maps DevicesRanOn to GET /indicators/queries/devices/v1. "
            "PSFalcon public/indicators.ps1 Get-FalconIocHost wraps this read with type/value and offset/limit.",
        ),
    ),
    FalconOperation(
        id="ProcessesRanOn",
        method="GET",
        path="/indicators/queries/processes/v1",
        scopes=("IOCs (Indicators of Compromise):read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/iocs/#processesranon",
            doc_scope="IOCs (Indicators of Compromise): READ",
            falcon_mcp="falcon-mcp has no tool for ProcessesRanOn. "
            "falconpy/_endpoint/_iocs.py maps ProcessesRanOn to GET /indicators/queries/processes/v1. "
            "PSFalcon public/indicators.ps1 Get-FalconIocProcess wraps this read; device_id is required.",
        ),
    ),
    FalconOperation(
        id="entities_processes",
        method="GET",
        path="/processes/entities/processes/v1",
        scopes=("IOCs (Indicators of Compromise):read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/iocs/#entitiesprocesses",
            doc_scope="IOCs (Indicators of Compromise): READ",
            falcon_mcp="falcon-mcp has no tool for entities_processes. "
            "falconpy/_endpoint/_iocs.py maps entities_processes to GET /processes/entities/processes/v1. "
            "PSFalcon public/indicators.ps1 Get-FalconIocProcess -Id wraps this read with ids query parameters.",
        ),
    ),
    FalconOperation(
        id="queryCombinedHostGroups",
        method="GET",
        path="/devices/combined/host-groups/v1",
        scopes=("Host Groups:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/host-group/#querycombinedhostgroups",
            doc_scope="Host groups: READ",
            falcon_mcp="falcon_mcp/common/api_scopes.py maps queryCombinedHostGroups to Host Groups:read; "
            "falcon_mcp/modules/host_groups.py search_host_groups returns id/name/group_type/description",
        ),
    ),
    FalconOperation(
        id="queryCombinedGroupMembers",
        method="GET",
        path="/devices/combined/host-group-members/v1",
        scopes=("Host Groups:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/host-group/#querycombinedgroupmembers",
            doc_scope="Host groups: READ",
            falcon_mcp="falcon_mcp/common/api_scopes.py maps queryCombinedGroupMembers to Host Groups:read; "
            "falcon_mcp/modules/host_groups.py search_host_group_members uses id and returns host entities",
        ),
    ),
    FalconOperation(
        id="combined_hosts",
        method="GET",
        path="/discover/combined/hosts/v1",
        scopes=("Assets:read",),
        effect="read",
        evidence=Evidence(
            doc_url=DISCOVER_DOC,
            doc_scope="Assets: READ",
            falcon_mcp="falcon_mcp/common/api_scopes.py maps combined_hosts to Assets:read; "
            "falcon_mcp/modules/discover.py search_managed_assets and search_unmanaged_assets use it. "
            "falconpy/_endpoint/_discover.py and the official API reference specify after pagination and a 1000 ceiling.",
        ),
    ),
    FalconOperation(
        id="combined_applications",
        method="GET",
        path="/discover/combined/applications/v1",
        scopes=("Assets:read",),
        effect="read",
        evidence=Evidence(
            doc_url=DISCOVER_DOC,
            doc_scope="Assets: READ",
            falcon_mcp="falcon_mcp/common/api_scopes.py maps combined_applications to Assets:read; "
            "falcon_mcp/modules/discover.py search_applications uses it; "
            "falconpy/_endpoint/_discover.py specifies after pagination.",
        ),
    ),
    FalconOperation(
        id="get_hosts",
        method="GET",
        path="/discover/entities/hosts/v1",
        scopes=("Assets:read",),
        effect="read",
        evidence=Evidence(
            doc_url=DISCOVER_DOC,
            doc_scope="Assets: READ",
            falcon_mcp="falcon-mcp has no tool for get_hosts. "
            "falconpy/_endpoint/_discover.py maps get_hosts to GET /discover/entities/hosts/v1. "
            "PSFalcon public/discover.ps1 Get-FalconAsset wraps this read with ids in the query.",
        ),
    ),
    FalconOperation(
        id="query_logins",
        method="GET",
        path="/discover/queries/logins/v1",
        scopes=("Assets:read",),
        effect="read",
        evidence=Evidence(
            doc_url=DISCOVER_DOC,
            doc_scope="Assets: READ",
            falcon_mcp="falcon-mcp has no tool for query_logins. "
            "falconpy/_endpoint/_discover.py maps query_logins to GET /discover/queries/logins/v1. "
            "PSFalcon public/discover.ps1 Get-FalconAsset -Login wraps this offset-paginated read.",
        ),
    ),
    FalconOperation(
        id="get_logins",
        method="GET",
        path="/discover/entities/logins/v1",
        scopes=("Assets:read",),
        effect="read",
        evidence=Evidence(
            doc_url=DISCOVER_DOC,
            doc_scope="Assets: READ",
            falcon_mcp="falcon-mcp has no tool for get_logins. "
            "falconpy/_endpoint/_discover.py maps get_logins to GET /discover/entities/logins/v1. "
            "PSFalcon public/discover.ps1 Get-FalconAsset wraps this read with at most 100 ids in the query.",
        ),
    ),
    FalconOperation(
        id="QueryGetNetworkAddressHistoryV1",
        method="POST",
        path="/devices/combined/devices/network-address-history/v1",
        scopes=("Hosts:read",),
        effect="read",
        evidence=Evidence(
            doc_url=HOSTS_DOC,
            doc_scope="Hosts: READ",
            falcon_mcp="falcon-mcp has no tool for QueryGetNetworkAddressHistoryV1. "
            "falconpy/_endpoint/_hosts.py maps QueryGetNetworkAddressHistoryV1 to POST "
            "/devices/combined/devices/network-address-history/v1. "
            "PSFalcon public/devices.ps1 Get-FalconHost -Network wraps this read with body ids.",
        ),
    ),
    FalconOperation(
        id="QuerySensorsByFilter",
        method="GET",
        path="/identity-protection/queries/devices/v1",
        scopes=("Identity Protection Entities:read",),
        effect="read",
        evidence=Evidence(
            doc_url=IDENTITY_PROTECTION_DOC + "#querysensorsbyfilter",
            doc_scope="Identity Protection Entities: READ",
            falcon_mcp=(
                "falcon-mcp has no tool for QuerySensorsByFilter (falcon_mcp/modules/idp.py). "
                "falconpy/_endpoint/_identity_protection.py maps QuerySensorsByFilter to GET "
                "/identity-protection/queries/devices/v1. "
                "PSFalcon Get-FalconIdentityHost in public/identity-protection.ps1 wraps the same operation."
            ),
        ),
    ),
    FalconOperation(
        id="GetSensorDetails",
        method="POST",
        path="/identity-protection/entities/devices/GET/v1",
        scopes=("Identity Protection Entities:read",),
        effect="read",
        evidence=Evidence(
            doc_url=IDENTITY_PROTECTION_DOC + "#getsensordetails",
            doc_scope="Identity Protection Entities: READ",
            falcon_mcp=(
                "falcon-mcp has no tool for GetSensorDetails (falcon_mcp/modules/idp.py). "
                "falconpy/_endpoint/_identity_protection.py maps GetSensorDetails to POST "
                "/identity-protection/entities/devices/GET/v1. "
                "PSFalcon Get-FalconIdentityHost -Id in public/identity-protection.ps1 wraps the same operation."
            ),
        ),
    ),
    FalconOperation(
        id="QueryVulnerabilities",
        method="GET",
        path="/intel/queries/vulnerabilities/v1",
        scopes=("Vulnerabilities (Falcon Intelligence):read",),
        effect="read",
        evidence=Evidence(
            doc_url=INTEL_DOC,
            doc_scope="Vulnerabilities (Falcon Intelligence): READ",
            falcon_mcp=(
                "falcon-mcp has no tool for QueryVulnerabilities (falcon_mcp/modules/intel.py). "
                "falconpy/_endpoint/_intel.py maps QueryVulnerabilities to GET /intel/queries/vulnerabilities/v1; "
                "PSFalcon public/intel.ps1 Get-FalconCve wraps the same route with filter, limit and offset."
            ),
        ),
    ),
    FalconOperation(
        id="getVulnerabilities",
        method="GET",
        path="/spotlight/entities/vulnerabilities/v2",
        scopes=("Vulnerabilities:read",),
        effect="read",
        evidence=Evidence(
            doc_url=SPOTLIGHT_DOC,
            doc_scope="Vulnerabilities: READ",
            falcon_mcp=(
                "falcon-mcp has no tool for getVulnerabilities; falcon_mcp/modules/spotlight.py "
                "exposes only combinedQueryVulnerabilities. "
                "falconpy/_endpoint/_spotlight_vulnerabilities.py maps getVulnerabilities to GET "
                "/spotlight/entities/vulnerabilities/v2 with ids; "
                "PSFalcon public/spotlight.ps1 Get-FalconVulnerability wraps the same route."
            ),
        ),
    ),
    FalconOperation(
        id="QueryIntelActorEntities",
        method="GET",
        path="/intel/combined/actors/v1",
        scopes=("Actors (Falcon Intelligence):read",),
        effect="read",
        evidence=Evidence(
            doc_url=INTEL_DOC,
            doc_scope="Actors (Falcon Intelligence): READ",
            falcon_mcp="falcon_mcp/common/api_scopes.py maps QueryIntelActorEntities to Actors (Falcon Intelligence):read; "
            "falcon_mcp/modules/intel.py query_actor_entities (search_actors) uses the combined endpoint",
        ),
    ),
    FalconOperation(
        id="GetIntelActorEntities",
        method="GET",
        path="/intel/entities/actors/v1",
        scopes=("Actors (Falcon Intelligence):read",),
        effect="read",
        evidence=Evidence(
            doc_url=INTEL_DOC,
            doc_scope="Actors (Falcon Intelligence): READ",
            falcon_mcp="falcon-mcp has no tool for GetIntelActorEntities. "
            "falconpy/_endpoint/_intel.py maps GetIntelActorEntities to GET /intel/entities/actors/v1. "
            "PSFalcon Get-FalconActor in public/intel.ps1 wraps this entity read with ids and fields.",
        ),
    ),
    FalconOperation(
        id="QueryIntelReportEntities",
        method="GET",
        path="/intel/combined/reports/v1",
        scopes=("Reports (Falcon Intelligence):read",),
        effect="read",
        evidence=Evidence(
            doc_url=INTEL_DOC,
            doc_scope="Reports (Falcon Intelligence): READ",
            falcon_mcp="falcon_mcp/common/api_scopes.py maps QueryIntelReportEntities to Reports (Falcon Intelligence):read; "
            "falcon_mcp/modules/intel.py query_report_entities (search_reports) uses the combined endpoint",
        ),
    ),
    FalconOperation(
        id="GetIntelReportEntities",
        method="GET",
        path="/intel/entities/reports/v1",
        scopes=("Reports (Falcon Intelligence):read",),
        effect="read",
        evidence=Evidence(
            doc_url=INTEL_DOC,
            doc_scope="Reports (Falcon Intelligence): READ",
            falcon_mcp="falcon-mcp has no tool for GetIntelReportEntities. "
            "falconpy/_endpoint/_intel.py maps GetIntelReportEntities to GET /intel/entities/reports/v1. "
            "PSFalcon Get-FalconIntel in public/intel.ps1 wraps this entity read with ids and fields.",
        ),
    ),
    FalconOperation(
        id="GetMitreReport",
        method="GET",
        path="/intel/entities/mitre-reports/v1",
        scopes=("Actors (Falcon Intelligence):read",),
        effect="read",
        evidence=Evidence(
            doc_url=INTEL_DOC,
            doc_scope="Actors (Falcon Intelligence): READ",
            falcon_mcp="falcon_mcp/common/api_scopes.py maps GetMitreReport to Actors (Falcon Intelligence):read; "
            "falcon_mcp/modules/intel.py get_mitre_report requests format=json and parses a top-level JSON list",
        ),
    ),
    FalconOperation(
        id="QueryIntelIndicatorEntities",
        method="GET",
        path="/intel/combined/indicators/v1",
        scopes=("Indicators (Falcon Intelligence):read",),
        effect="read",
        evidence=Evidence(
            doc_url=INTEL_DOC,
            doc_scope="Indicators (Falcon Intelligence): READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps QueryIntelIndicatorEntities to "
                "Indicators (Falcon Intelligence):read; falcon_mcp/modules/intel.py search_indicators "
                "uses filter, limit, sort and the combined response fields. "
                "falconpy/_endpoint/_intel.py corroborates these parameters; "
                "https://developer.crowdstrike.com/sdks/python/responses/ documents _marker pagination."
            ),
        ),
    ),
    FalconOperation(
        id="cloud_security_assets_queries",
        method="GET",
        path="/cloud-security-assets/queries/resources/v1",
        scopes=("Cloud Security API Assets:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/cloud-security-assets/",
            doc_scope="Cloud Security API Assets: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps cloud_security_assets_queries to Cloud Security API Assets:read; "
                "falcon_mcp/modules/cloud/cloud_assets.py search_cspm_assets uses filter/limit/after/sort; "
                "falconpy/_endpoint/_cloud_security_assets.py confirms GET /cloud-security-assets/queries/resources/v1"
            ),
        ),
    ),
    FalconOperation(
        id="GetIntelIndicatorEntities",
        method="POST",
        path="/intel/entities/indicators/GET/v1",
        scopes=("Indicators (Falcon Intelligence):read",),
        effect="read",
        evidence=Evidence(
            doc_url=INTEL_DOC,
            doc_scope="Indicators (Falcon Intelligence): READ",
            falcon_mcp=(
                "falcon-mcp has no tool for GetIntelIndicatorEntities. "
                "falconpy/_endpoint/_intel.py maps GetIntelIndicatorEntities to POST "
                "/intel/entities/indicators/GET/v1. PSFalcon Get-FalconIndicator in public/intel.ps1 "
                "wraps the same operation with an ids body."
            ),
        ),
    ),
    FalconOperation(
        id="cloud_security_assets_entities_get",
        method="GET",
        path="/cloud-security-assets/entities/resources/v1",
        scopes=("Cloud Security API Assets:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/cloud-security-assets/",
            doc_scope="Cloud Security API Assets: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps cloud_security_assets_entities_get to Cloud Security API Assets:read; "
                "falcon_mcp/modules/cloud/cloud_base.py _batch_get_cspm_assets uses GET ids batches of 100; "
                "modules/cloud/cloud_assets.py _slim_cspm_asset documents resource and cloud_context fields; "
                "falconpy/_endpoint/_cloud_security_assets.py confirms GET /cloud-security-assets/entities/resources/v1"
            ),
        ),
    ),
    FalconOperation(
        id="cspm_evaluations_iom_queries",
        method="GET",
        path="/cloud-security-evaluations/queries/ioms/v1",
        scopes=("Cloud Security API Detections:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/cloud-security-detections/",
            doc_scope="Cloud Security API Detections: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps cspm_evaluations_iom_queries to Cloud Security API Detections:read; "
                "falcon_mcp/modules/cloud/cloud_iom.py search_iom_findings uses filter/limit/offset/sort; "
                "falconpy/_endpoint/_cloud_security_detections.py confirms GET /cloud-security-evaluations/queries/ioms/v1"
            ),
        ),
    ),
    FalconOperation(
        id="cspm_evaluations_iom_entities",
        method="GET",
        path="/cloud-security-evaluations/entities/ioms/v1",
        scopes=("Cloud Security API Detections:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/cloud-security-detections/",
            doc_scope="Cloud Security API Detections: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps cspm_evaluations_iom_entities to Cloud Security API Detections:read; "
                "falcon_mcp/modules/cloud/cloud_iom.py _batch_get_iom_entities uses GET ids batches of 100; "
                "search_iom_findings documents evaluation, cloud and resource response nesting; "
                "falconpy/_endpoint/_cloud_security_detections.py confirms GET /cloud-security-evaluations/entities/ioms/v1"
            ),
        ),
    ),
    FalconOperation(
        id="combined_cloud_risks",
        method="GET",
        path="/cloud-security-risks/combined/cloud-risks/v1",
        scopes=("Cloud Security API Risks:read",),
        effect="read",
        evidence=Evidence(
            doc_url="https://developer.crowdstrike.com/api-reference/collections/cloud-security/",
            doc_scope="Cloud Security API Risks: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps combined_cloud_risks to Cloud Security API Risks:read; "
                "falcon_mcp/modules/cloud/cloud_risks.py search_cloud_risks uses filter/limit/offset/sort; "
                "falconpy/_endpoint/_cloud_security.py confirms GET /cloud-security-risks/combined/cloud-risks/v1"
            ),
        ),
    ),
    FalconOperation(
        id="PostAggregatesAlertsV2",
        method="POST",
        path="/alerts/aggregates/alerts/v2",
        scopes=("Alerts:read",),
        effect="read",
        evidence=Evidence(
            doc_url=ALERTS_DOC,
            doc_scope="Alerts: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps PostAggregatesAlertsV2 to Alerts:read; "
                "falcon_mcp/modules/detections.py aggregate_detections and modules/base.py "
                "_base_aggregate use a list of terms specs and name/buckets/label/count results; "
                "falconpy/_endpoint/_alerts.py confirms POST /alerts/aggregates/alerts/v2"
            ),
        ),
    ),
    FalconOperation(
        id="GetQueriesAlertsV2",
        method="GET",
        path="/alerts/queries/alerts/v2",
        scopes=("Alerts:read",),
        effect="read",
        evidence=Evidence(
            doc_url=ALERTS_DOC,
            doc_scope="Alerts: READ",
            falcon_mcp="falcon_mcp/common/api_scopes.py maps GetQueriesAlertsV2 to Alerts:read for search_detections",
        ),
    ),
    FalconOperation(
        id="PostEntitiesAlertsV2",
        method="POST",
        path="/alerts/entities/alerts/v2",
        scopes=("Alerts:read",),
        effect="read",
        evidence=Evidence(
            doc_url=ALERTS_DOC,
            doc_scope="Alerts: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps PostEntitiesAlertsV2 to Alerts:read "
                "as the hydrate step of search_detections"
            ),
        ),
    ),
    FalconOperation(
        id="QueryDevicesByFilter",
        method="GET",
        path="/devices/queries/devices/v1",
        scopes=("Hosts:read",),
        effect="read",
        evidence=Evidence(
            doc_url=HOSTS_DOC,
            doc_scope="Hosts: READ",
            falcon_mcp="falcon_mcp/common/api_scopes.py maps QueryDevicesByFilter to Hosts:read for search_hosts",
        ),
    ),
    FalconOperation(
        id="PostDeviceDetailsV2",
        method="POST",
        path="/devices/entities/devices/v2",
        scopes=("Hosts:read",),
        effect="read",
        evidence=Evidence(
            doc_url=HOSTS_DOC,
            doc_scope="Hosts: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps PostDeviceDetailsV2 to Hosts:read for search_hosts and get_host_details"
            ),
        ),
    ),
    FalconOperation(
        id="combinedQueryVulnerabilities",
        method="GET",
        path="/spotlight/combined/vulnerabilities/v1",
        scopes=("Vulnerabilities:read",),
        effect="read",
        evidence=Evidence(
            doc_url=SPOTLIGHT_DOC,
            doc_scope="Vulnerabilities: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps combinedQueryVulnerabilities to "
                "Vulnerabilities:read for search_vulnerabilities"
            ),
        ),
    ),
    FalconOperation(
        id="GetVulnerabilities",
        method="POST",
        path="/intel/entities/vulnerabilities/GET/v1",
        scopes=("Vulnerabilities (Falcon Intelligence):read",),
        effect="read",
        evidence=Evidence(
            doc_url=INTEL_DOC,
            doc_scope="Vulnerabilities (Falcon Intelligence): READ",
            falcon_mcp=(
                "falcon-mcp has no tool for GetVulnerabilities. "
                "falconpy/_endpoint/_intel.py maps GetVulnerabilities to POST "
                "/intel/entities/vulnerabilities/GET/v1. PSFalcon Get-FalconCve wraps the same operation."
            ),
        ),
    ),
    FalconOperation(
        id="QueryDeviceLoginHistoryV2",
        method="POST",
        path="/devices/combined/devices/login-history/v2",
        scopes=("Hosts:read",),
        effect="read",
        evidence=Evidence(
            doc_url=HOSTS_DOC,
            doc_scope="Hosts: READ",
            falcon_mcp=(
                "falcon-mcp has no tool for QueryDeviceLoginHistoryV2. "
                "falconpy/_endpoint/_hosts.py maps QueryDeviceLoginHistoryV2 to POST "
                "/devices/combined/devices/login-history/v2. PSFalcon Get-FalconHost -Login wraps the same operation."
            ),
        ),
    ),
    FalconOperation(
        id="query_accounts",
        method="GET",
        path="/discover/queries/accounts/v1",
        scopes=("Assets:read",),
        effect="read",
        evidence=Evidence(
            doc_url=DISCOVER_DOC,
            doc_scope="Assets: READ",
            falcon_mcp=(
                "falcon-mcp has no tool for query_accounts. "
                "falconpy/_endpoint/_discover.py maps query_accounts to GET /discover/queries/accounts/v1. "
                "PSFalcon Get-FalconAsset -Account wraps the same operation."
            ),
        ),
    ),
    FalconOperation(
        id="get_accounts",
        method="GET",
        path="/discover/entities/accounts/v1",
        scopes=("Assets:read",),
        effect="read",
        evidence=Evidence(
            doc_url=DISCOVER_DOC,
            doc_scope="Assets: READ",
            falcon_mcp=(
                "falcon-mcp has no tool for get_accounts. "
                "falconpy/_endpoint/_discover.py maps get_accounts to GET /discover/entities/accounts/v1. "
                "PSFalcon Get-FalconAsset -Account -Id wraps the same operation."
            ),
        ),
    ),
    FalconOperation(
        id="StartSearchV1",
        method="POST",
        path="/humio/api/v1/repositories/{repository}/queryjobs",
        scopes=SEARCH_LIFECYCLE_SCOPES,
        effect="search-lifecycle",
        evidence=Evidence(
            doc_url=NGSIEM_DOC,
            doc_scope="NGSIEM: WRITE",
            falcon_mcp="falcon_mcp/common/api_scopes.py maps StartSearchV1 to NGSIEM:write for search_ngsiem",
        ),
    ),
    FalconOperation(
        id="GetSearchStatusV1",
        method="GET",
        path="/humio/api/v1/repositories/{repository}/queryjobs/{id}",
        scopes=("NGSIEM:read",),
        effect="read",
        evidence=Evidence(
            doc_url=NGSIEM_DOC,
            doc_scope="NGSIEM: READ",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps GetSearchStatusV1 to NGSIEM:read as the poll step of search_ngsiem"
            ),
        ),
    ),
    FalconOperation(
        id="StopSearchV1",
        method="DELETE",
        path="/humio/api/v1/repositories/{repository}/queryjobs/{id}",
        scopes=SEARCH_LIFECYCLE_SCOPES,
        effect="search-lifecycle",
        evidence=Evidence(
            doc_url=NGSIEM_DOC,
            doc_scope="NGSIEM: WRITE",
            falcon_mcp="falcon_mcp/common/api_scopes.py maps StopSearchV1 to NGSIEM:write for search_ngsiem cleanup",
        ),
    ),
    FalconOperation(
        id="api_preempt_proxy_post_graphql",
        method="POST",
        path="/identity-protection/combined/graphql/v1",
        scopes=GRAPHQL_QUERY_SCOPES,
        effect="graphql-query",
        evidence=Evidence(
            doc_url=IDENTITY_PROTECTION_DOC,
            doc_scope="Identity Protection GraphQL: WRITE",
            falcon_mcp=(
                "falcon_mcp/common/api_scopes.py maps api_preempt_proxy_post_graphql to Identity Protection "
                "Entities, Timeline, Detections, and Assessment :read plus Identity Protection GraphQL:write "
                "for idp_investigate_entity, which builds only `query` documents"
            ),
        ),
    ),
)

#: Routes whose shape marks a Falcon mutation; no registered operation may match one (§3.3 property 5).
MUTATION_ROUTE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"/entities/[^/]+/action", re.IGNORECASE),
    re.compile(r"/queries/[^/]+/action", re.IGNORECASE),
)

# Passive history is the entire RTR read admission (§4.5), including the separate audit collection.
RTR_HISTORY_ROUTES = MappingProxyType(
    {
        "RTR_ListAllSessions": ("GET", "/real-time-response/queries/sessions/v1", ("Real time response:read",)),
        "RTR_ListSessions": ("POST", "/real-time-response/entities/sessions/GET/v1", ("Real time response:read",)),
        "RTRAuditSessions": ("GET", "/real-time-response-audit/combined/sessions/v1", ("Real time response audit:read",)),
    }
)

_READ_SCOPE = re.compile(r":\s*READ$", re.IGNORECASE)
_WRITE_SCOPE = re.compile(r":\s*WRITE$", re.IGNORECASE)

#: A path variable is the only caller-supplied value that reaches a URL path (§3.3 property 7).
PATH_VARIABLE = re.compile(r"\{([a-z_]+)\}")
_PATH_SEPARATORS = ("/", "\\", "%")
_DOT_SEGMENTS = (".", "..")


def _seal_effect(entry: FalconOperation) -> None:
    """The four enforcement tiers (§3.3 properties 2, 4, and 9).

    A read must cite a `: READ` scope and use a read verb. The `search-lifecycle` tier exists only
    for the ids captain exception N1 names, and each must cite `NGSIEM: WRITE` and carry exactly
    the one write scope the exception admits. The `graphql-query` tier exists only for the one id
    captain exception N2 names, which must cite `Identity Protection GraphQL: WRITE`, carry exactly
    that scope, and be a POST. No other write scope is representable in any tier.
    """
    if entry.id in RTR_EXECUTION_IDS or entry.effect == "rtr-read-only-execute":
        if (
            RTR_EXECUTION_TUPLES.get(entry.id) != (entry.method, entry.path, entry.effect, entry.scopes)
            or entry.evidence.doc_scope != "Real time response: READ"
        ):
            raise ValueError(f"operation {entry.id} is outside captain exception N3")
        return
    if entry.effect == "read":
        if not _READ_SCOPE.search(entry.evidence.doc_scope):
            raise ValueError(f"operation {entry.id} does not cite a read scope")
        if entry.method not in ("GET", "POST"):
            raise ValueError(f"operation {entry.id} has an unsupported method")
        if any(scope.endswith(":write") for scope in entry.scopes):
            raise ValueError(f"operation {entry.id} is a read but declares a write scope")
        return
    if entry.effect == "graphql-query":
        if entry.id not in GRAPHQL_QUERY_IDS:
            raise ValueError(f"operation {entry.id} is not admitted by captain exception N2")
        if not _WRITE_SCOPE.search(entry.evidence.doc_scope):
            raise ValueError(f"operation {entry.id} does not cite the Identity Protection GraphQL write scope")
        if entry.scopes != GRAPHQL_QUERY_SCOPES:
            raise ValueError(f"operation {entry.id} declares a scope outside captain exception N2")
        if entry.method != "POST":
            raise ValueError(f"operation {entry.id} has an unsupported method")
        return
    if entry.effect != "search-lifecycle":
        raise ValueError(f"operation {entry.id} declares an unknown effect")
    if entry.id not in SEARCH_LIFECYCLE_IDS:
        raise ValueError(f"operation {entry.id} is not admitted by captain exception N1")
    if not _WRITE_SCOPE.search(entry.evidence.doc_scope):
        raise ValueError(f"operation {entry.id} does not cite the NGSIEM write scope")
    if entry.scopes != SEARCH_LIFECYCLE_SCOPES:
        raise ValueError(f"operation {entry.id} declares a scope outside captain exception N1")
    if entry.method not in ("POST", "DELETE"):
        raise ValueError(f"operation {entry.id} has an unsupported method")


def _second_citation(entry: FalconOperation) -> bool:
    """§2.2: falcon-mcp, or falconpy's generated table plus PSFalcon when falcon-mcp has no tool."""
    text = entry.evidence.falcon_mcp
    if "api_scopes.py" in text and "maps " in text:
        return True
    return (
        f"falcon-mcp has no tool for {entry.id}" in text
        and "falconpy/_endpoint/" in text
        and f"maps {entry.id} to {entry.method} {entry.path}" in text
        and "PSFalcon " in text
    )


def _seal(entry: FalconOperation) -> FalconOperation:
    _seal_effect(entry)
    if not entry.path.startswith("/"):
        raise ValueError(f"operation {entry.id} has a malformed path")
    if not entry.scopes:
        raise ValueError(f"operation {entry.id} declares no scope")
    if not (entry.evidence.doc_url and entry.evidence.doc_scope and entry.evidence.falcon_mcp):
        raise ValueError(f"operation {entry.id} is missing evidence")
    if not _second_citation(entry):
        raise ValueError(f"operation {entry.id} is missing its §2.2 corroboration")
    if any(pattern.search(entry.path) for pattern in MUTATION_ROUTE_PATTERNS):
        raise ValueError(f"operation {entry.id} matches a known mutation route")
    if entry.id not in RTR_EXECUTION_IDS and (entry.id in RTR_HISTORY_ROUTES or "/real-time-response" in entry.path.lower()):
        if entry.effect != "read" or RTR_HISTORY_ROUTES.get(entry.id) != (entry.method, entry.path, entry.scopes):
            raise ValueError(f"operation {entry.id} is outside the exact RTR history routes")
    return entry


#: The frozen registry. Every descriptor, its `scopes` tuple, its `evidence`, and this mapping are immutable.
OPERATIONS: Mapping[str, FalconOperation] = MappingProxyType({entry.id: _seal(entry) for entry in CANONICAL})


def operation(id: str) -> FalconOperation:
    """Resolves the canonical descriptor for an operation id.

    Deny by default: an id that is not a key of the registry, or a descriptor whose own id
    disagrees with its key or whose effect is outside the sealed union, fails with
    READ_ONLY_VIOLATION before any request is prepared.
    """
    resolved = OPERATIONS.get(id)
    if resolved is None or resolved.id != id or resolved.effect not in EFFECTS:
        raise CliError(
            "READ_ONLY_VIOLATION",
            f"operation {id} is not a registered falcon-axi operation",
            ["falcon-axi issues only the operations in its closed registry; report this as a bug"],
        )
    return resolved


def path_arguments(descriptor: FalconOperation, supplied: Mapping[str, str]) -> dict[str, str]:
    """Validates the path variables a route interpolates (§3.3 property 7).

    A path variable is the only caller-supplied value that reaches a URL path, so a separator or a
    whole-value dot segment could retarget the request at a route the resolved descriptor never
    selected, defeating the closed registry. falcon-mcp guards `repository` for the same reason;
    falcon-axi guards every variable of every route, because the search id is caller-supplied too.
    """
    required = set(PATH_VARIABLE.findall(descriptor.path))
    if set(supplied) != required:
        raise CliError(
            "READ_ONLY_VIOLATION",
            f"operation {descriptor.id} was prepared with the wrong path variables",
            ["falcon-axi interpolates only the path variables its registry declares; report this as a bug"],
        )
    if descriptor.id == "combined_summary_get" and supplied.get("vertex_type") != "processes":
        raise CliError("READ_ONLY_VIOLATION", "ThreatGraph summaries are restricted to processes")
    for name, value in supplied.items():
        if not value.strip() or any(character in value for character in _PATH_SEPARATORS) or value in _DOT_SEGMENTS:
            raise CliError(
                "VALIDATION_ERROR",
                f"the {name} must be a plain name",
                [
                    "`/`, `\\`, and `%` are refused, and so are `.` and `..`, because the value reaches a URL path",
                    "Pass a bare repository or search name, for example `search-all`",
                ],
            )
    return dict(supplied)


def registered_scopes(ids: Sequence[str]) -> tuple[str, ...]:
    """The scopes the registered operations require, for operator provisioning (§5.7)."""
    return tuple(sorted({scope for id in ids for scope in operation(id).scopes}))

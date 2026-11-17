import type { Credential } from "./credentials.js";
import { CliError } from "./core.js";
import type { Invocation } from "./parser.js";
import { readJsonInput, runGatedWrite } from "./raw.js";
import { readOnly } from "./rtr-policy.js";
import { requestException } from "./transport/https.js";
import {
  policyRuleCreateBody,
  policyRuleDeleteTarget,
} from "./transport/policy-rule.js";

const route = "/identity-protection/entities/policy-rules/v1";

export async function identityRuleCreate(
  invocation: Invocation,
  credential: Credential,
  base: string,
  allowUnknown: boolean,
  signal: AbortSignal,
): Promise<void> {
  const file = invocation.flags.get("--body-file");
  if (file === undefined)
    throw new CliError(
      "VALIDATION_ERROR",
      "identity rule create requires --body-file",
    );
  const executing = invocation.flags.has("--execute");
  if (invocation.flags.has("--confirm") && !executing)
    throw new CliError("VALIDATION_ERROR", "--confirm requires --execute");
  if (executing && readOnly())
    throw new CliError(
      "READ_ONLY_VIOLATION",
      "FALCON_AXI_READ_ONLY forbids identity policy rule writes",
    );
  const input = readJsonInput(file, "--body-file");
  const canonical = policyRuleCreateBody(input.value);
  const body = JSON.stringify(canonical);
  await runGatedWrite({
    operationName: "identity-rule-create",
    method: "POST",
    path: route,
    query: "",
    body,
    executing,
    confirm: invocation.flags.get("--confirm"),
    credential,
    base,
    allowUnknown,
    signal,
    refusal: [
      "identity rule create requires explicit profile opt-in",
      'Set "writes": {"allowWrites": true, "operations": ["identity-rule-create"]} on the selected file profile',
    ],
    label: "identity rule create",
    pendingHelp: [
      "Add --execute --confirm '<confirm>' to send this request once; it is never replayed automatically",
      "identity rule create reads no target state and detects no no-ops; reconcile an unknown outcome before retrying",
    ],
    send: (session) =>
      requestException(
        "post_policy_rules",
        session.base,
        session.token,
        { body: canonical },
        allowUnknown,
        signal,
      ),
  });
}

export async function identityRuleDelete(
  invocation: Invocation,
  credential: Credential,
  base: string,
  allowUnknown: boolean,
  signal: AbortSignal,
): Promise<void> {
  const executing = invocation.flags.has("--execute");
  if (invocation.flags.has("--confirm") && !executing)
    throw new CliError("VALIDATION_ERROR", "--confirm requires --execute");
  if (executing && readOnly())
    throw new CliError(
      "READ_ONLY_VIOLATION",
      "FALCON_AXI_READ_ONLY forbids identity policy rule writes",
    );
  const target = policyRuleDeleteTarget(invocation.id);
  await runGatedWrite({
    operationName: "identity-rule-delete",
    method: "DELETE",
    path: route,
    query: target.slice(route.length + 1),
    body: "",
    executing,
    confirm: invocation.flags.get("--confirm"),
    credential,
    base,
    allowUnknown,
    signal,
    refusal: [
      "identity rule delete requires explicit profile opt-in",
      'Set "writes": {"allowWrites": true, "operations": ["identity-rule-delete"]} on the selected file profile',
    ],
    label: "identity rule delete",
    pendingHelp: [
      "Add --execute --confirm '<confirm>' to send this request once; it is never replayed automatically",
      "identity rule delete reads no target state and detects no no-ops; reconcile an unknown outcome before retrying",
    ],
    send: (session) =>
      requestException(
        "delete_policy_rules",
        session.base,
        session.token,
        { ids: invocation.id! },
        allowUnknown,
        signal,
      ),
  });
}

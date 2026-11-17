import { CliError, object } from "../core.js";

const actions = [
  "ADD_TO_WATCH_LIST",
  "ALLOW",
  "APPLY_SSO_POLICY",
  "BLOCK",
  "FORCE_PASSWORD_CHANGE",
  "MFA",
] as const;
const triggers = [
  "access",
  "accountEvent",
  "alert",
  "federatedAccess",
] as const;
const fields = [
  "name",
  "action",
  "trigger",
  "enabled",
  "simulationMode",
  "activity",
  "destination",
  "sourceEndpoint",
  "sourceUser",
] as const;

function invalid(message: string): never {
  throw new CliError("VALIDATION_ERROR", message);
}

function strings(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string"))
    invalid(`${label} must be an array of strings`);
  return value as string[];
}

function condition(
  value: unknown,
  label: string,
): { exclude?: string[]; include?: string[] } {
  if (!object(value)) invalid(`${label} must be an object`);
  const keys = Object.keys(value);
  if (
    keys.length === 0 ||
    keys.some((key) => key !== "exclude" && key !== "include")
  )
    invalid(`${label} accepts only exclude and include`);
  return {
    ...(value.exclude === undefined
      ? {}
      : { exclude: strings(value.exclude, `${label}.exclude`) }),
    ...(value.include === undefined
      ? {}
      : { include: strings(value.include, `${label}.include`) }),
  };
}

function group(
  value: unknown,
  label: string,
  allowed: readonly string[],
): Record<string, unknown> {
  if (!object(value)) invalid(`${label} must be an object`);
  const keys = Object.keys(value);
  if (keys.length === 0 || keys.some((key) => !allowed.includes(key)))
    invalid(`${label} has an unexpected field`);
  const result: Record<string, unknown> = {};
  for (const key of allowed)
    if (value[key] !== undefined)
      result[key] = condition(value[key], `${label}.${key}`);
  return result;
}

export function policyRuleCreateBody(value: unknown): Record<string, unknown> {
  if (!object(value)) invalid("the policy rule body must be one JSON object");
  if (
    Object.keys(value).some(
      (key) => !(fields as readonly string[]).includes(key),
    )
  )
    invalid("the policy rule body has an unexpected field");
  if (typeof value.name !== "string") invalid("name must be a string");
  if (
    typeof value.action !== "string" ||
    !(actions as readonly string[]).includes(value.action)
  )
    invalid(
      "action must be ADD_TO_WATCH_LIST, ALLOW, APPLY_SSO_POLICY, BLOCK, FORCE_PASSWORD_CHANGE, or MFA",
    );
  if (
    typeof value.trigger !== "string" ||
    !(triggers as readonly string[]).includes(value.trigger)
  )
    invalid("trigger must be access, accountEvent, alert, or federatedAccess");
  if (typeof value.enabled !== "boolean") invalid("enabled must be a boolean");
  if (typeof value.simulationMode !== "boolean")
    invalid("simulationMode must be a boolean");
  return {
    action: value.action,
    enabled: value.enabled,
    name: value.name,
    simulationMode: value.simulationMode,
    trigger: value.trigger,
    ...(value.activity === undefined
      ? {}
      : {
          activity: group(value.activity, "activity", [
            "accessType",
            "accessTypeCustom",
          ]),
        }),
    ...(value.destination === undefined
      ? {}
      : {
          destination: group(value.destination, "destination", [
            "entityId",
            "groupMembership",
          ]),
        }),
    ...(value.sourceEndpoint === undefined
      ? {}
      : {
          sourceEndpoint: group(value.sourceEndpoint, "sourceEndpoint", [
            "entityId",
            "groupMembership",
          ]),
        }),
    ...(value.sourceUser === undefined
      ? {}
      : {
          sourceUser: group(value.sourceUser, "sourceUser", [
            "entityId",
            "groupMembership",
          ]),
        }),
  };
}

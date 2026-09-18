import assert from "node:assert/strict";
import test from "node:test";
import { CliError } from "../../src/core.js";
import { assertTrustedOrigin, regionOf, REGIONS, resolveBaseUrl } from "../../src/origin.js";

const SECRET = "synthetic-client-secret";

function rejection(url: string, allowUnknown = false): CliError {
  try {
    assertTrustedOrigin(url, allowUnknown);
  } catch (error) {
    assert.ok(error instanceof CliError);
    return error;
  }
  throw new Error(`expected ${url} to be refused`);
}

test("every documented region is a trusted origin", () => {
  for (const [name, url] of Object.entries(REGIONS)) {
    assert.equal(assertTrustedOrigin(url), url);
    assert.equal(regionOf(url), name);
  }
});

test("a CrowdStrike subdomain is trusted and a lookalike host is not", () => {
  assert.equal(assertTrustedOrigin("https://api.us-3.crowdstrike.com"), "https://api.us-3.crowdstrike.com");
  assert.equal(rejection("https://api.crowdstrike.com.example").details.invalid_component, "host");
});

test("each violated component is reported by name and never with the URL", () => {
  const cases: Array<[string, string]> = [
    ["http://api.crowdstrike.com", "scheme"],
    [`https://user:${SECRET}@api.crowdstrike.com`, "userinfo"],
    ["https://api.crowdstrike.com:8443", "port"],
    ["https://api.crowdstrike.com/internal", "path"],
    [`https://api.crowdstrike.com/?probe=${SECRET}`, "query"],
    ["https://api.crowdstrike.com/#fragment", "fragment"],
    ["not-a-url", "scheme"],
  ];
  for (const [url, component] of cases) {
    const error = rejection(url);
    assert.equal(error.code, "ORIGIN_NOT_ALLOWED");
    assert.equal(error.details.invalid_component, component);
    const rendered = [error.message, ...error.help].join("\n");
    assert.ok(!rendered.includes(SECRET), `${component} rendering leaked a value`);
    assert.ok(!rendered.includes("8443") && !rendered.includes("internal"));
  }
});

test("--allow-unknown-origin relaxes only the host allowlist", () => {
  assert.equal(assertTrustedOrigin("https://api.unknown-cloud.example", true), "https://api.unknown-cloud.example");
  assert.equal(rejection("http://api.unknown-cloud.example", true).details.invalid_component, "scheme");
  assert.equal(rejection("https://api.unknown-cloud.example/path", true).details.invalid_component, "path");
});

test("region precedence is flag, then environment, then the default cloud", () => {
  assert.equal(resolveBaseUrl({ region: "eu-1", envBaseUrl: "https://api.us-2.crowdstrike.com" }), REGIONS["eu-1"]);
  assert.equal(resolveBaseUrl({ envBaseUrl: "https://api.us-2.crowdstrike.com" }), "https://api.us-2.crowdstrike.com");
  assert.equal(resolveBaseUrl({}), REGIONS["us-1"]);
  assert.equal(resolveBaseUrl({ region: "https://api.laggar.gcw.crowdstrike.com" }), "https://api.laggar.gcw.crowdstrike.com");
  assert.throws(() => resolveBaseUrl({ region: "us-9" }), (error: unknown) => error instanceof CliError && error.code === "VALIDATION_ERROR");
});

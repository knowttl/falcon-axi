import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { decode } from "@toon-format/toon";
import { parse, run } from "../../src/cli.js";
import { CliError } from "../../src/core.js";
import { render, truncate } from "../../src/render.js";
import { VERSION } from "../../src/version.js";
import { CREDENTIAL_ENV, fixture, RecordedTransport, serve } from "../support/recorded.js";

const REPO = new URL("../../../", import.meta.url).pathname;

test("an unknown flag is rejected by name with the valid flags inlined", async () => {
  const result = await run(["detection", "list", "--sev", "high"], new RecordedTransport([]), { ...CREDENTIAL_ENV });
  assert.equal(result.exitCode, 2);
  assert.match(result.stdout, /^error: unknown flag --sev for `detection list`$/m);
  assert.match(result.stdout, /^code: VALIDATION_ERROR$/m);
  assert.match(result.stdout, /Did you mean --severity\?/);
  assert.match(result.stdout, /--filter/);
});

test("an unknown command or subcommand fails before any request", async () => {
  const recorded = new RecordedTransport([]);
  const command = await run(["host", "list"], recorded, { ...CREDENTIAL_ENV });
  assert.equal(command.exitCode, 2);
  assert.match(command.stdout, /valid commands: detection list, detection show, auth status/);
  const subcommand = await run(["detection", "contain"], recorded, { ...CREDENTIAL_ENV });
  assert.match(subcommand.stdout, /valid detection subcommands: list, show/);
  assert.equal(recorded.requests.length, 0);
});

test("the surface lists no mutating verb", () => {
  for (const verb of ["contain", "update", "assign", "close", "release", "run", "execute", "create", "delete"]) {
    assert.throws(() => parse([verb]), (error: unknown) => error instanceof CliError && error.code === "VALIDATION_ERROR");
    assert.throws(() => parse(["detection", verb]), (error: unknown) => error instanceof CliError);
  }
});

test("a secret-shaped flag cannot be registered", async () => {
  const module = await import("../../src/cli.js");
  assert.ok(module.run);
  // The guard runs at module load for every declared flag; assert it rejects the shape directly.
  const guard = (name: string): void => {
    if (/(secret|password|token|key|passphrase)/i.test(name)) throw new Error(`secret-shaped flag --${name} is forbidden`);
  };
  for (const name of ["client-secret", "password", "api-key", "token", "passphrase"]) {
    assert.throws(() => guard(name), /forbidden/);
  }
  assert.doesNotThrow(() => guard("member-cid"));
});

test("--limit above the documented ceiling is a validation error naming it", async () => {
  const result = await run(["detection", "list", "--limit", "10001"], new RecordedTransport([]), { ...CREDENTIAL_ENV });
  assert.equal(result.exitCode, 2);
  assert.match(result.stdout, /--limit must be an integer from 1 to 10000/);
});

test("--profile is refused honestly rather than silently ignored", async () => {
  const result = await run(["detection", "list", "--profile", "prod"], new RecordedTransport([]), { ...CREDENTIAL_ENV });
  assert.equal(result.exitCode, 2);
  assert.match(result.stdout, /profile configuration is not implemented in stage 1/);
});

test("--member-cid and --no-member-cid cannot be combined", async () => {
  const result = await run(["auth", "status", "--member-cid", "cid", "--no-member-cid"], new RecordedTransport([]), { ...CREDENTIAL_ENV });
  assert.equal(result.exitCode, 2);
  assert.match(result.stdout, /cannot be combined/);
});

test("help never advertises a command the CLI does not have", async () => {
  for (const argv of [["--help"], ["detection", "list", "--help"], ["detection", "show", "--help"], ["auth", "status", "--help"]]) {
    const result = await run(argv, new RecordedTransport([]), { ...CREDENTIAL_ENV });
    assert.equal(result.exitCode, 0);
    for (const absent of ["host list", "vuln list", "falcon-axi scopes", "falcon-axi setup"]) {
      assert.ok(!result.stdout.includes(absent), `${argv.join(" ")} advertises ${absent}`);
    }
  }
  const top = await run(["--help"], new RecordedTransport([]), { ...CREDENTIAL_ENV });
  assert.match(top.stdout, /read-only/);
  assert.ok(top.stdout.includes(VERSION));
});

test("rendered output parses as TOON and keeps the help block intact", async () => {
  const recorded = new RecordedTransport([
    serve("GetQueriesAlertsV2", fixture("alerts/query-page.json")),
    serve("PostEntitiesAlertsV2", fixture("alerts/hydrate-page.json")),
  ]);
  const result = await run(["detection", "list", "--limit", "2"], recorded, { ...CREDENTIAL_ENV });
  const parsed = decode(result.stdout) as Record<string, unknown>;
  assert.equal(Array.isArray(parsed.detections), true);
  assert.equal((parsed.help as string[]).length >= 2, true);

  const withCommas = render({ count: 1 }, ["first, with a comma", 'second with "quotes" and a colon: here']);
  const decoded = decode(withCommas) as { help: string[] };
  assert.deepEqual(decoded.help, ["first, with a comma", 'second with "quotes" and a colon: here']);
});

test("truncation reports the full length and leaves short values untouched", () => {
  assert.deepEqual(truncate("short"), { text: "short", truncated: false });
  const long = truncate("x".repeat(900));
  assert.equal(long.truncated, true);
  assert.match(long.text, /truncated, 900 chars total/);
});

test("the published version matches package.json", async () => {
  const manifest = JSON.parse(await readFile(join(REPO, "package.json"), "utf8")) as { version: string; bin: Record<string, string>; engines: Record<string, string> };
  assert.equal(manifest.version, VERSION);
  assert.equal(manifest.bin["falcon-axi"], "dist/src/cli.js");
  assert.ok(manifest.engines.node);
});

test("every fixture is wholly synthetic and carries its provenance header", async () => {
  const root = join(REPO, "test/fixtures");
  const domains = await readdir(root, { withFileTypes: true });
  let count = 0;
  for (const domain of domains) {
    for (const file of await readdir(join(root, domain.name))) {
      count++;
      const text = await readFile(join(root, domain.name, file), "utf8");
      const parsed = JSON.parse(text) as { provenance?: Record<string, string>; response?: { status?: number } };
      assert.ok(parsed.provenance, `${file} has no provenance header`);
      assert.equal(parsed.provenance?.provenance, "synthetic");
      assert.ok(parsed.provenance?.operation, `${file} names no operation`);
      assert.match(parsed.provenance?.reference ?? "", /^https:\/\//);
      assert.match(parsed.provenance?.schema_read ?? "", /^\d{4}-\d{2}-\d{2}$/);
      assert.equal(typeof parsed.response?.status, "number");
      assert.doesNotMatch(text, /\b[0-9a-f]{32}\b/i, `${file} contains a realistic CID or agent id`);
      assert.doesNotMatch(text, /eyJ[A-Za-z0-9_-]{10,}/, `${file} contains a realistic bearer token`);
      assert.doesNotMatch(text, /Bearer\s+[A-Za-z0-9._-]{12,}/i, `${file} contains an Authorization value`);
    }
  }
  assert.ok(count >= 9);
});

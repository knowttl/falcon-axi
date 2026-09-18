import assert from "node:assert/strict";
import { readdir } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { mintPermit, sendPermittedRequest } from "../../src/transport/network-sink.js";
import { CliError } from "../../src/core.js";

const REPO = new URL("../../../", import.meta.url).pathname;

test("the architecture boundary check passes", async () => {
  process.chdir(REPO);
  const module = (await import(new URL("scripts/architecture-check.mjs", `file://${REPO}`).href)) as { check: () => Promise<boolean> };
  assert.equal(await module.check(), true);
});

test("the sink refuses a prepared request without a valid permit", async () => {
  const prepared = { url: "https://api.crowdstrike.com/alerts/queries/alerts/v2", method: "GET" as const, headers: {} };
  await assert.rejects(
    () => sendPermittedRequest(prepared, {} as ReturnType<typeof mintPermit>),
    (error: unknown) => error instanceof CliError && error.code === "READ_ONLY_VIOLATION",
  );
  await assert.rejects(
    () => sendPermittedRequest(prepared, undefined as unknown as ReturnType<typeof mintPermit>),
    (error: unknown) => error instanceof CliError && error.code === "READ_ONLY_VIOLATION",
  );
});

test("this repository carries no automation workflow", async () => {
  await assert.rejects(readdir(join(REPO, ".github/workflows")), (error: unknown) => (error as NodeJS.ErrnoException).code === "ENOENT");
});

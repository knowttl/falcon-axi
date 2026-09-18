import assert from "node:assert/strict";
import { chmod, mkdtemp, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { CliError } from "../../src/core.js";
import { resolveCredential } from "../../src/credentials.js";

const MISSING = join(tmpdir(), "falcon-axi-absent", "credentials");

function env(values: Record<string, string | undefined>): NodeJS.ProcessEnv {
  return { FALCON_AXI_CREDENTIALS_FILE: MISSING, ...values };
}

test("both environment variables resolve as one atomic pair", async () => {
  const credential = await resolveCredential(env({ FALCON_CLIENT_ID: "id", FALCON_CLIENT_SECRET: "secret" }));
  assert.equal(credential?.channel, "environment");
  assert.equal(credential?.clientId, "id");
});

test("half an environment credential stops resolution and names the missing half", async () => {
  for (const [present, missing] of [
    ["FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET"],
    ["FALCON_CLIENT_SECRET", "FALCON_CLIENT_ID"],
  ]) {
    await assert.rejects(
      () => resolveCredential(env({ [present as string]: "value" })),
      (error: unknown) => {
        assert.ok(error instanceof CliError);
        assert.equal(error.code, "CREDENTIAL_INCOMPLETE");
        assert.equal(error.exitCode, 2);
        assert.ok(error.message.includes(missing as string));
        return true;
      },
    );
  }
});

test("no credential anywhere resolves to nothing", async () => {
  assert.equal(await resolveCredential(env({})), undefined);
});

test("a protected credentials file is read and a loose one is refused unread", async () => {
  const directory = await mkdtemp(join(tmpdir(), "falcon-axi-credentials-"));
  const path = join(directory, "credentials");
  await writeFile(path, "FALCON_CLIENT_ID=file-id\nFALCON_CLIENT_SECRET=file-secret\n", { mode: 0o600 });
  const credential = await resolveCredential(env({ FALCON_AXI_CREDENTIALS_FILE: path }));
  assert.equal(credential?.channel, "file");
  assert.equal(credential?.clientId, "file-id");

  await chmod(path, 0o640);
  await assert.rejects(
    () => resolveCredential(env({ FALCON_AXI_CREDENTIALS_FILE: path })),
    (error: unknown) => {
      assert.ok(error instanceof CliError);
      assert.equal(error.code, "VALIDATION_ERROR");
      assert.ok(!error.message.includes("file-secret"));
      return true;
    },
  );

  const link = join(directory, "linked-credentials");
  await symlink(path, link);
  await assert.rejects(
    () => resolveCredential(env({ FALCON_AXI_CREDENTIALS_FILE: link })),
    (error: unknown) => error instanceof CliError && error.code === "VALIDATION_ERROR",
  );
});

test("a credentials file holding one half of the pair is incomplete", async () => {
  const directory = await mkdtemp(join(tmpdir(), "falcon-axi-credentials-"));
  const path = join(directory, "credentials");
  await writeFile(path, "FALCON_CLIENT_ID=file-id\n", { mode: 0o600 });
  await assert.rejects(
    () => resolveCredential(env({ FALCON_AXI_CREDENTIALS_FILE: path })),
    (error: unknown) => error instanceof CliError && error.code === "CREDENTIAL_INCOMPLETE",
  );
});

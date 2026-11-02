import assert from "node:assert/strict";
import { test } from "node:test";
import { writeFile, chmod, symlink, mkdir, readdir } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { decode } from "@toon-format/toon";
import {
  run,
  reset,
  recordings,
  wire,
  directory,
  config,
  tokenResponse,
  recordedResponse,
  prepareScenario,
} from "./s01.test.js";
import "./golden.test.js";
import "./safety.test.js";

if (process.env.S01_ACTIVE_PATH !== "artium") {
  test("review R1 explicitly empty profile refuses environment fallback", async () => {
    reset();
    const result = await run(["auth", "status"], {
      FALCON_AXI_PROFILE: "",
    });
    assert.equal(result.code, 1);
    assert.match(result.stdout, /PROFILE_NOT_FOUND/);
    assert.equal(wire.length, 0);
  });

  for (const group of [
    "detection",
    "host",
    "auth",
    "config",
    "profile",
    "ioc",
    "process",
    "file-change",
    "rtr",
    "rtr session",
    "rtr audit",
  ])
    test(`review R5 ${group} help requires terminal input`, async () => {
      reset();
      const args = [...group.split(" "), "--help"];
      assert.equal((await run(args)).code, 0);
      for (const trailing of ["--unexpected", "extra", "--help"])
        assert.equal((await run([...args, trailing])).code, 2);
      assert.equal(wire.length, 0);
    });

  for (const source of ["own", "flag", "environment", "profile", "cleared"])
    for (const retargeted of [false, true])
      test(`review R2 home labels ${source} tenant with retarget=${retargeted}`, async () => {
        const member = "synthetic-child-1234";
        await prepareScenario({
          name: "home-tenant",
          argv: [],
          exit_code: 0,
          responders: [
            {
              op: "GetQueriesAlertsV2",
              generate: { kind: "ids", count: 0, total: 0 },
            },
          ],
          oauth: retargeted
            ? [
                {
                  response: {
                    status: 308,
                    headers: { "x-cs-region": "us-2" },
                    body: {},
                  },
                },
                {
                  response: {
                    status: 200,
                    body: { access_token: "synthetic-s01-token" },
                  },
                },
              ]
            : [
                {
                  response: {
                    status: 200,
                    body: { access_token: "synthetic-s01-token" },
                  },
                },
              ],
        });
        const extra: NodeJS.ProcessEnv = {};
        const args: string[] = [];
        if (source === "flag") args.push("--member-cid", member);
        if (source === "environment") {
          extra.FALCON_AXI_PROFILE = undefined;
          extra.FALCON_AXI_MEMBER_CID = member;
        }
        if (source === "profile" || source === "cleared") {
          extra.FALCON_AXI_CONFIG = join(directory, "home-member.json");
          await writeFile(
            extra.FALCON_AXI_CONFIG,
            JSON.stringify({
              version: 1,
              profiles: {
                artium: {
                  clientId: "synthetic-s01-client",
                  memberCid: member,
                  clientSecret: { env: "ARTIUM_SECRET_0" },
                },
              },
            }),
            { mode: 0o600 },
          );
        }
        if (source === "cleared") args.push("--no-member-cid");
        const result = await run(args, extra);
        assert.equal(result.code, 0, result.stdout);
        const data = decode(result.stdout) as { tenant: string };
        const selected = !["own", "cleared"].includes(source);
        assert.equal(
          data.tenant,
          `${retargeted ? "us-2 (re-targeted from us-1)" : "us-1"}${selected ? " member CID …1234" : " (own CID unavailable)"}`,
        );
        assert.ok(!result.stdout.includes(member));
        assert.equal(
          new URLSearchParams(wire[0]!.body).get("member_cid"),
          selected ? member : null,
        );
      });

  for (const [command, fixture] of [
    ["logins", "hosts/login-history.json"],
    ["network", "discover/network-history.json"],
  ])
    for (const elapsed of [35000, 60001])
      test(`review R3 host ${command} hostname budget after ${elapsed}ms`, async () => {
        reset();
        await recordings([fixture!]);
        recordedResponse("QueryDevicesByFilter", 200, {
          meta: { pagination: { total: 1 } },
          resources: ["synthetic-device-01"],
          errors: [],
        });
        const result = await run(
          ["host", command!, "--hostname", "WIN-DC-01"],
          {
            NODE_OPTIONS: `--import=${fileURLToPath(new URL("./history-clock.js", import.meta.url))}`,
            S03_ELAPSED_MS: String(elapsed),
          },
        );
        if (elapsed < 60000) {
          assert.equal(result.code, 0, result.stdout);
          assert.match(result.stdout, /synthetic-device-01/);
          assert.equal(wire.length, 3);
        } else {
          assert.equal(result.code, 1, result.stdout);
          assert.match(result.stdout, /WAIT_TIMEOUT/);
          assert.match(result.stdout, /combined 60-second time budget/);
          assert.ok(!wire.some((request) => request.url.includes("/devices/")));
        }
      });
}

for (const args of [
  ["-x"],
  ["detection", "list", "-x"],
  ["detection", "show", "synthetic", "-x"],
])
  test(`AC-FLAGS short flag is named before credentials: ${args.join(" ")}`, async () => {
    reset();
    const result = await run(args, {
      FALCON_AXI_CONFIG: "/missing/config.json",
    });
    assert.equal(result.code, 2);
    assert.match(result.stdout, /unknown flag -x/);
    assert.match(result.stdout, /valid flags for/);
    assert.equal(wire.length, 0);
  });

if (process.env.S01_ACTIVE_PATH !== "artium") {
  test("SR-146 credential owner mismatch refuses before file content", async () => {
    reset();
    const result = await run(["auth", "status"], {
      NODE_OPTIONS: `--import=${fileURLToPath(new URL("./file-race.js", import.meta.url))}`,
      S02_OWNER_MISMATCH: "1",
    });
    assert.equal(result.code, 1);
    assert.match(result.stdout, /CONFIG_INSECURE/);
    assert.equal(wire.length, 0);
  });
  test("C16 config replacement after inspection refuses attacker content", async () => {
    reset();
    const path = join(directory, "race-config.json");
    const target = join(directory, "race-attacker.json");
    await writeFile(
      path,
      JSON.stringify({
        version: 1,
        profiles: { artium: { clientId: "synthetic-race-safe" } },
      }),
      { mode: 0o600 },
    );
    await writeFile(
      target,
      JSON.stringify({
        version: 1,
        profiles: {
          artium: {
            clientId: "CANARY-attacker-id",
            clientSecret: { env: "ARTIUM_SECRET_0" },
          },
        },
      }),
      { mode: 0o600 },
    );
    const result = await run(["auth", "status"], {
      FALCON_AXI_CONFIG: path,
      NODE_OPTIONS: `--import=${fileURLToPath(new URL("./file-race.js", import.meta.url))}`,
      S02_RACE_CONFIG: path,
      S02_RACE_TARGET: target,
    });
    assert.equal(result.code, 2);
    assert.match(result.stdout, /CONFIG_INVALID/);
    assert.ok(!result.stdout.includes("CANARY-attacker-id"));
    assert.equal(wire.length, 0);
  });
  for (const closeInput of [true, false])
    test(`C21 invalid argv refuses promptly with ${closeInput ? "closed" : "held-open"} stdin`, async () => {
      reset();
      const result = await run(
        [
          "detection",
          "show",
          "synthetic-id",
          "--client-secret",
          "CANARY-argv-secret",
        ],
        { FALCON_AXI_CONFIG: "/missing/config.json" },
        false,
        closeInput,
      );
      assert.equal(result.code, 2);
      assert.match(result.stdout, /unknown flag --client-secret/);
      assert.ok(
        !(result.stdout + result.stderr).includes("CANARY-argv-secret"),
      );
      assert.equal(wire.length, 0);
    });
  test("C01/C02 config paths use only absolute XDG roots and stay local", async () => {
    reset();
    for (const roots of ["absolute", "relative"]) {
      const root = roots === "absolute" ? directory : "relative-root";
      const result = await run(["config", "path"], {
        FALCON_AXI_CONFIG: undefined,
        XDG_CONFIG_HOME: root,
        XDG_STATE_HOME: root,
      });
      assert.equal(result.code, 0);
      const data = decode(result.stdout) as {
        config: string;
        write_log: string;
      };
      assert.equal(
        data.config,
        join(
          directory,
          roots === "absolute" ? "" : ".config",
          "falcon-axi/config.json",
        ),
      );
      assert.equal(
        data.write_log,
        join(
          directory,
          roots === "absolute" ? "" : ".local/state",
          "falcon-axi/writes.log",
        ),
      );
    }
    assert.equal(wire.length, 0);
  });
  test("C04 profile list selects its config without resolving SecretRefs", async () => {
    reset();
    const path = join(directory, "names-only.json");
    await writeFile(
      path,
      JSON.stringify({
        version: 1,
        profiles: {
          alternate: {
            clientId: "synthetic-alternate-id",
            clientSecret: { env: "MISSING_SECRET" },
          },
        },
      }),
      { mode: 0o600 },
    );
    const result = await run(["profile", "list", "--config", path]);
    assert.equal(result.code, 0);
    assert.deepEqual(decode(result.stdout), { profiles: ["alternate"] });
    assert.equal(wire.length, 0);
  });
  test("C05/C09 explicit file identity ignores competing environment fields", async () => {
    reset();
    const result = await run(["auth", "status"], {
      FALCON_AXI_REGION: "eu-1",
      FALCON_AXI_MEMBER_CID: "synthetic-competing-member",
    });
    assert.equal(result.code, 0, result.stdout);
    const data = decode(result.stdout) as Record<string, unknown>;
    assert.equal(data.profile, "artium");
    assert.equal(data.endpoint, "https://api.crowdstrike.com");
    assert.equal(data.client_secret_source, "env:ARTIUM_SECRET_0");
    assert.equal(wire.length, 1);
    const sent = new URLSearchParams(wire[0]!.body);
    assert.equal(sent.get("client_id"), "synthetic-s01-client");
    assert.equal(sent.has("member_cid"), false);
  });
  for (const missing of ["FALCON_AXI_CLIENT_ID", "FALCON_AXI_CLIENT_SECRET"])
    test(`C08 incomplete environment pair refuses file fallback: ${missing}`, async () => {
      reset();
      const result = await run(["auth", "status"], {
        FALCON_AXI_PROFILE: undefined,
        [missing]: undefined,
      });
      assert.equal(result.code, 2);
      assert.match(result.stdout, /CONFIG_INVALID/);
      assert.match(result.stdout, new RegExp(missing));
      assert.equal(wire.length, 0);
    });
  for (const profiles of [
    {},
    { A: { clientId: "synthetic-A" }, B: { clientId: "synthetic-B" } },
  ])
    test(`C06 no implicit choice among ${Object.keys(profiles).length} profiles`, async () => {
      reset();
      const path = join(directory, "ambiguous.json");
      await writeFile(path, JSON.stringify({ version: 1, profiles }), {
        mode: 0o600,
      });
      const result = await run(["auth", "status"], {
        FALCON_AXI_CONFIG: path,
        FALCON_AXI_PROFILE: undefined,
        FALCON_AXI_CLIENT_ID: undefined,
        FALCON_AXI_CLIENT_SECRET: undefined,
      });
      assert.equal(result.code, 1);
      assert.match(
        result.stdout,
        Object.keys(profiles).length ? /PROFILE_AMBIGUOUS/ : /PROFILE_REQUIRED/,
      );
      assert.equal(wire.length, 0);
    });
  test("C07 absent selected profile never falls back", async () => {
    reset();
    const result = await run(["auth", "status", "--profile", "absent"]);
    assert.equal(result.code, 1);
    assert.match(result.stdout, /PROFILE_NOT_FOUND/);
    assert.equal(wire.length, 0);
  });
  for (const [name, profile] of [
    ["unknown field", { clientId: "synthetic-A", surprise: true }],
    [
      "inline secret",
      { clientId: "synthetic-A", clientSecret: "CANARY-inline-secret" },
    ],
    [
      "ambiguous ref",
      {
        clientId: "synthetic-A",
        clientSecret: { env: "SECRET", file: "/tmp/unused" },
      },
    ],
    [
      "invalid ref",
      { clientId: "synthetic-A", clientSecret: { env: "BAD-NAME" } },
    ],
    [
      "relative file",
      { clientId: "synthetic-A", clientSecret: { file: "relative-secret" } },
    ],
  ] as const)
    test(`C10/C11 validates even unselected profile: ${name}`, async () => {
      reset();
      const path = join(directory, "invalid.json");
      await writeFile(
        path,
        JSON.stringify({
          version: 1,
          profiles: { good: { clientId: "synthetic-good" }, bad: profile },
        }),
        { mode: 0o600 },
      );
      const result = await run(["profile", "list", "--config", path]);
      assert.equal(result.code, 2);
      assert.match(result.stdout, /CONFIG_INVALID/);
      assert.ok(!result.stdout.includes("CANARY-inline-secret"));
      assert.equal(wire.length, 0);
    });
  test("C13 file secret accepts BOM and trims trailing whitespace", async () => {
    reset();
    const secret = join(directory, "private-secret");
    const path = join(directory, "file-profile.json");
    await writeFile(secret, "\uFEFFCANARY-file-secret\r\n  ", { mode: 0o400 });
    await writeFile(
      path,
      JSON.stringify({
        version: 1,
        profiles: {
          only: {
            clientId: "synthetic-file-id",
            clientSecret: { file: secret },
          },
        },
      }),
      { mode: 0o600 },
    );
    const result = await run([
      "auth",
      "status",
      "--config",
      path,
      "--profile",
      "only",
    ]);
    assert.equal(result.code, 0, result.stdout);
    assert.equal(
      new URLSearchParams(wire[0]!.body).get("client_secret"),
      "CANARY-file-secret",
    );
    assert.ok(!result.stdout.includes("CANARY-file-secret"));
  });
  test("C14 unsafe config and symlink secret are refused before OAuth", async () => {
    reset();
    const unsafe = join(directory, "unsafe.json");
    await writeFile(unsafe, "{}", { mode: 0o664 });
    await chmod(unsafe, 0o664);
    const first = await run(["auth", "status", "--config", unsafe]);
    assert.equal(first.code, 1);
    assert.match(first.stdout, /CONFIG_INSECURE/);
    const linked = join(directory, "linked-secret");
    await symlink(config, linked);
    const path = join(directory, "linked.json");
    await writeFile(
      path,
      JSON.stringify({
        version: 1,
        profiles: {
          only: { clientId: "synthetic-id", clientSecret: { file: linked } },
        },
      }),
      { mode: 0o600 },
    );
    const second = await run([
      "auth",
      "status",
      "--config",
      path,
      "--profile",
      "only",
    ]);
    assert.match(second.stdout, /CONFIG_INSECURE/);
    assert.equal(wire.length, 0);
  });
  test("C17 invocations mint separately and store no token", async () => {
    reset();
    const state = join(directory, "isolated-state");
    await mkdir(state);
    assert.equal(
      (await run(["auth", "status"], { XDG_STATE_HOME: state })).code,
      0,
    );
    assert.equal(
      (await run(["auth", "status"], { XDG_STATE_HOME: state })).code,
      0,
    );
    assert.equal(wire.length, 2);
    assert.deepEqual(await readdir(state), []);
  });
} else {
  for (const args of [
    ["config", "path"],
    ["profile", "list"],
  ])
    test(`S02 managed local command is refused: ${args.join(" ")}`, async () => {
      reset();
      const result = await run(args);
      assert.notEqual(result.code, 0);
      assert.match(result.stdout, /blocked|not allowed|INVALID_INPUT/i);
      assert.equal(wire.length, 0);
    });
  test("C22 managed auth status uses the private profile", async () => {
    reset();
    const result = await run(["auth", "status"]);
    assert.equal(result.code, 0, result.stdout);
    assert.match(result.stdout, /profile: artium/);
    assert.match(result.stdout, /credential_channel: file/);
    assert.equal(
      wire.filter((request) => request.url === "/oauth2/token").length,
      1,
    );
  });
}

for (const entry of [
  {
    args: ["host", "list", "--limit", "2"],
    fixtures: ["hosts/query-page.json", "hosts/details-page.json"],
    expected:
      /hosts\[2\]\{device_id,hostname,platform,last_seen\}:\n  synthetic-device-01,WIN-DC-01,Windows/,
  },
  {
    args: ["detection", "summary"],
    fixtures: ["alerts/aggregate-severity.json"],
    expected: /Critical,12/,
  },
  {
    args: ["detection", "show", "ldt:synthetic-agent-01:1001"],
    fixtures: ["alerts/hydrate-detail.json"],
    expected: /powershell/i,
  },
  {
    args: ["detection", "process", "ldt:synthetic-agent:1001"],
    fixtures: ["alerts/hydrate-lineage.json"],
    expected: /synthetic-grandparent.exe/,
  },
  {
    args: ["host", "logins", "synthetic-device-01"],
    fixtures: ["hosts/login-history.json"],
    expected: /synthetic-svc-backup/,
  },
  {
    args: ["host", "network", "synthetic-device-01"],
    fixtures: ["discover/network-history.json"],
    expected: /192\.0\.2\.10/,
  },
  {
    args: ["ioc", "list"],
    fixtures: ["ioc/query-page.json", "ioc/details-page.json"],
    expected: /iocs\[2\]\{id,type,value,action\}/,
  },
  {
    args: ["ioc", "show", "synthetic-ioc-01"],
    fixtures: ["ioc/details-page.json"],
    expected: /example.invalid/,
  },
  {
    args: ["file-change", "show", "synthetic-change-01"],
    fixtures: ["filevantage/changes.json"],
    expected: /synthetic-editor --example/,
  },
  {
    args: ["process", "show", "pid:00000000000000000000000000000001:1234"],
    fixtures: ["migration/S03/process-details.json"],
    expected: /synthetic-child.exe/,
  },
  {
    args: ["ioc", "hosts", "domain:example.invalid"],
    fixtures: ["ioc/hosts-page.json"],
    expected: /synthetic-device-01/,
  },
  {
    args: [
      "ioc",
      "processes",
      "domain:example.invalid",
      "--host",
      "synthetic-device-01",
    ],
    fixtures: ["ioc/processes-page.json"],
    expected: /pid:synthetic-device-01:1234/,
  },
  {
    args: ["file-change", "list"],
    fixtures: ["filevantage/query.json", "filevantage/changes.json"],
    expected: /\/synthetic\/first.conf/,
  },
  {
    args: ["rtr", "session", "list", "--limit", "2"],
    fixtures: ["rtr/ids.json", "rtr/sessions.json"],
    expected:
      /sessions\[2\]\{id,hostname,user_id,created_at\}:\n  synthetic-session-01/,
  },
  {
    args: ["rtr", "session", "show", "synthetic-session-01"],
    fixtures: ["rtr/sessions.json"],
    expected: /SYNTHETIC-HOST-01/,
  },
  {
    args: ["rtr", "audit", "list"],
    fixtures: ["rtr/audit.json"],
    expected: /synthetic-session-01/,
  },
  {
    args: ["process", "tree", "pid:synthetic-device:3"],
    fixtures: ["threatgraph/process-tree.json", "threatgraph/children.json"],
    expected: /synthetic-root.exe/,
  },
])
  test(`S03 installed ${entry.args.join(" ")} preserves retained data`, async () => {
    reset();
    await recordings(entry.fixtures);
    const result = await run(entry.args);
    assert.equal(result.code, 0, result.stdout + result.stderr);
    assert.match(result.stdout, entry.expected);
    assert.ok(
      !wire.some((request) => /\/entities\/sessions\/v1$/.test(request.url)),
      "passive history must not initialize a session",
    );
  });

test("S03 installed host show preserves retained data with a valid synthetic id", async () => {
  await prepareScenario({
    name: "host-show",
    argv: ["host", "show", "00000000000000000000000000000001"],
    exit_code: 0,
    responders: [
      {
        op: "PostDeviceDetailsV2",
        response: {
          status: 200,
          body: {
            resources: [
              {
                device_id: "00000000000000000000000000000001",
                hostname: "SYNTHETIC-HOST",
              },
            ],
          },
        },
      },
    ],
  });
  const result = await run([
    "host",
    "show",
    "00000000000000000000000000000001",
  ]);
  assert.equal(result.code, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /hostname: SYNTHETIC-HOST/);
});

if (process.env.S01_ACTIVE_PATH !== "artium") {
  test("C12 missing explicit SecretRef never tries a competing secret", async () => {
    reset();
    const result = await run(["auth", "status"], {
      ARTIUM_SECRET_0: undefined,
    });
    assert.equal(result.code, 1);
    assert.match(result.stdout, /AUTH_REQUIRED/);
    assert.equal(wire.length, 0);
  });
  test("C18 legacy file refuses environment fallback without reading its contents", async () => {
    reset();
    const home = join(directory, "legacy-home");
    await mkdir(join(home, ".config/falcon-axi"), { recursive: true });
    await writeFile(
      join(home, ".config/falcon-axi/credentials"),
      "CANARY-legacy-content",
      { mode: 0o600 },
    );
    const result = await run(["auth", "status"], {
      HOME: home,
      FALCON_AXI_CONFIG: join(home, "absent.json"),
      FALCON_AXI_PROFILE: undefined,
    });
    assert.equal(result.code, 1);
    assert.match(result.stdout, /CONFIG_MOVED/);
    assert.ok(!result.stdout.includes("CANARY-legacy-content"));
    assert.equal(wire.length, 0);
  });
  test("C19 canonical identity wins deprecated aliases with source-only notices", async () => {
    reset();
    const result = await run(["auth", "status"], {
      FALCON_AXI_PROFILE: undefined,
      FALCON_CLIENT_ID: "CANARY-deprecated-id",
      FALCON_CLIENT_SECRET: "CANARY-deprecated-secret",
    });
    assert.equal(result.code, 0, result.stdout);
    const sent = new URLSearchParams(wire[0]!.body);
    assert.equal(sent.get("client_id"), "synthetic-wrong-server-id");
    assert.match(
      result.stderr,
      /FALCON_CLIENT_ID is deprecated; use FALCON_AXI_CLIENT_ID/,
    );
    assert.ok(!(result.stdout + result.stderr).includes("CANARY-deprecated"));
  });
  for (const status of [401, 403])
    test(`C22 token refusal ${status} remains an authentication failure`, async () => {
      reset();
      tokenResponse(status, { errors: [{ message: "synthetic refusal" }] });
      const result = await run(["auth", "status"]);
      assert.equal(result.code, 1);
      assert.match(result.stdout, /AUTH_FAILED/);
      assert.equal(wire.length, 1);
    });
}
for (const entry of [
  {
    args: ["detection", "show", "synthetic-missing"],
    operation: "PostEntitiesAlertsV2",
    body: { resources: [] },
    expected: "NOT_FOUND",
  },
  {
    args: ["host", "show", "00000000000000000000000000000099"],
    operation: "PostDeviceDetailsV2",
    body: { resources: [] },
    expected: "NOT_FOUND",
  },
  {
    args: ["file-change", "list"],
    operation: "highVolumeQueryChanges",
    body: { resources: [null] },
    expected: "UPSTREAM_ERROR",
  },
  {
    args: ["process", "show", "pid:00000000000000000000000000000001:1234"],
    operation: "entities_processes",
    body: { resources: [] },
    expected: "UPSTREAM_ERROR",
  },
  {
    args: ["rtr", "session", "list"],
    operation: "RTR_ListAllSessions",
    body: { resources: false },
    expected: "UPSTREAM_ERROR",
  },
])
  test(`S03 distinguishes malformed or missing ${entry.args.join(" ")}`, async () => {
    reset();
    recordedResponse(entry.operation, 200, entry.body);
    const result = await run(entry.args);
    assert.equal(result.code, 1);
    assert.match(result.stdout, new RegExp(`code: ${entry.expected}`));
    assert.ok(!result.stdout.includes("continuation_cursor"));
  });
for (const entry of [
  {
    args: ["host", "list"],
    operation: "QueryDevicesByFilter",
    scope: "Hosts:read",
  },
  {
    args: ["host", "network", "synthetic-device-01"],
    operation: "QueryGetNetworkAddressHistoryV1",
    scope: "Hosts:read",
  },
  {
    args: ["detection", "summary"],
    operation: "PostAggregatesAlertsV2",
    scope: "Alerts:read",
  },
  {
    args: ["ioc", "list"],
    operation: "indicator_search_v1",
    scope: "IOC Management:read",
  },
  {
    args: ["file-change", "list"],
    operation: "highVolumeQueryChanges",
    scope: "Falcon FileVantage:read",
  },
  {
    args: ["rtr", "session", "list"],
    operation: "RTR_ListAllSessions",
    scope: "Real time response:read",
  },
  {
    args: ["process", "tree", "pid:synthetic-device:3"],
    operation: "combined_summary_get",
    scope: "Threatgraph:read",
  },
])
  test(`S03 scope refusal names the actual grant: ${entry.scope}`, async () => {
    reset();
    recordedResponse(entry.operation, 403, {
      errors: [{ message: "synthetic scope refusal" }],
    });
    const result = await run(entry.args);
    assert.equal(result.code, 1);
    const value = decode(result.stdout) as {
      code: string;
      required_scopes: string[];
    };
    assert.equal(value.code, "SCOPE_DENIED");
    assert.deepEqual(value.required_scopes, [entry.scope]);
  });

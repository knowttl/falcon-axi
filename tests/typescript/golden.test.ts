import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile, writeFile } from "node:fs/promises";
import { resolve, join } from "node:path";
import { createHmac } from "node:crypto";
import s02 from "../fixtures/migration/S02/contracts.json" with { type: "json" };
import s03 from "../fixtures/migration/S03/contracts.json" with { type: "json" };
import s04 from "../fixtures/migration/S04/contracts.json" with { type: "json" };
import s05 from "../fixtures/migration/S05/contracts.json" with { type: "json" };
import { prepareScenario, run } from "./s01.test.js";
import type { Scenario } from "./s01.test.js";
import { expectedDocument } from "./discovery.js";
import type { DiscoveryDelta } from "./discovery.js";

if (process.env.S01_ACTIVE_PATH !== "artium")
  for (const name of [
    ...s02.goldenScenarioIds,
    ...s03.goldenScenarioIds,
    ...s04.goldenScenarioIds,
    ...s05.goldenScenarioIds,
  ]) {
    test(`golden ${name}`, async () => {
      const scenario = JSON.parse(
        await readFile(
          resolve("tests/golden/scenarios", `${name}.json`),
          "utf8",
        ),
      ) as Scenario & { typescriptMigration?: DiscoveryDelta };
      await prepareScenario(scenario);
      const args = [...scenario.argv];
      if (scenario.cursor) {
        const position = scenario.cursor.position;
        const fingerprint = createHmac("sha256", "synthetic-client-secret")
          .update(
            JSON.stringify({
              client_id: "synthetic-client-id",
              member_cid: null,
              model: "offset",
              operation: "GetQueriesAlertsV2",
              origin: "https://api.crowdstrike.com",
              position,
              query: null,
              sort: null,
            }),
          )
          .digest("hex");
        args.push(
          "--cursor",
          Buffer.from(
            JSON.stringify({
              operation: "GetQueriesAlertsV2",
              model: "offset",
              position,
              fingerprint,
            }),
          ).toString("base64url"),
        );
      }
      const result = await run(args, {
        FALCON_AXI_PROFILE: undefined,
        FALCON_AXI_CONFIG: "/nonexistent/falcon-axi/config.json",
        FALCON_AXI_CLIENT_ID: undefined,
        FALCON_AXI_CLIENT_SECRET: undefined,
        FALCON_CLIENT_ID:
          scenario.env === "none" ? undefined : "synthetic-client-id",
        FALCON_CLIENT_SECRET:
          scenario.env === "none" ? undefined : "synthetic-client-secret",
        ...scenario.envExtra,
      });
      if (process.env.S01_EVIDENCE_DIR)
        await writeFile(
          join(process.env.S01_EVIDENCE_DIR, `golden-${name}.actual.txt`),
          result.stdout,
        );
      const expected = await expectedDocument(
        name,
        scenario.typescriptMigration,
      );
      assert.equal(result.code, scenario.exit_code, result.stdout);
      assert.equal(result.stdout, expected);
    });
  }

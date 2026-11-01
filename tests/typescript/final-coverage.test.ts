import assert from "node:assert/strict";
import { test } from "node:test";
import { checkWorkflow } from "../../scripts/typescript/final-coverage.js";

test("Workflow safety ignores a harmless YAML comment", () => {
  assert.doesNotThrow(() =>
    checkWorkflow(`
# FALCON_AXI_LIVE must remain disabled.
jobs:
  verify:
    steps:
      - run: npm run verify
`),
  );
});

for (const [location, workflow] of [
  ["workflow", 'env:\n  "FALCON_AXI_LI\\u0056E": "1"'],
  ["job", 'jobs:\n  verify:\n    env:\n      "FALCON_AXI_LI\\u0056E": "1"'],
  [
    "step",
    'jobs:\n  verify:\n    steps:\n      - env:\n          "FALCON_AXI_LI\\u0056E": "1"\n        run: npm run verify',
  ],
  [
    "value",
    'jobs:\n  verify:\n    steps:\n      - run: "echo $FALCON_AXI_LI\\u0056E"',
  ],
] as const) {
  test(`Workflow safety rejects an escaped forbidden identifier in a ${location} setting`, () => {
    assert.throws(
      () => checkWorkflow(workflow),
      /Credential or live automation is forbidden/,
    );
  });
}

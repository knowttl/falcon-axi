import assert from "node:assert/strict";
import { test, beforeEach } from "node:test";
import { decode } from "@toon-format/toon";
import { run, reset, wire, recordedResponse } from "./s01.test.js";

beforeEach(reset);
const value = (stdout: string): Record<string, unknown> =>
  decode(stdout) as Record<string, unknown>;
const requests = (): typeof wire =>
  wire.filter((request) => request.url !== "/oauth2/token");
const args = (...rest: string[]): string[] => [
  "identity",
  "sensor",
  "aggregate",
  "--name",
  "by-status",
  "--type",
  "terms",
  "--field",
  "status",
  ...rest,
];
const result = {
  name: "by-status",
  doc_count_error_upper_bound: 0,
  sum_other_doc_count: 2,
  buckets: [
    { label: "healthy", count: 7, sub_aggregates: [] },
    { label: "unhealthy", count: 1 },
  ],
};

for (const [shape, body] of [
  ["a resources envelope", { resources: [result] }],
  ["a bare array", [result]],
] as const)
  test(`identity sensor aggregate reads ${shape} and sends the evidenced body`, async () => {
    recordedResponse("GetSensorAggregates", 200, body);
    const output = await run(
      args("--filter", "status:'healthy'", "--size", "5"),
    );
    assert.equal(output.code, 0, output.stdout);
    assert.equal(requests().length, 1);
    assert.equal(requests()[0]!.method, "POST");
    assert.equal(
      requests()[0]!.url,
      "/identity-protection/aggregates/devices/GET/v1",
    );
    assert.deepEqual(JSON.parse(requests()[0]!.body), {
      name: "by-status",
      type: "terms",
      field: "status",
      filter: "status:'healthy'",
      size: 5,
    });
    assert.deepEqual(value(output.stdout).aggregates, [
      {
        name: "by-status",
        doc_count_error_upper_bound: 0,
        sum_other_doc_count: 2,
        buckets: [
          { label: "healthy", count: 7 },
          { label: "unhealthy", count: 1 },
        ],
      },
    ]);
  });

test("identity sensor aggregate reports an empty result", async () => {
  recordedResponse("GetSensorAggregates", 200, { resources: [] });
  const output = await run(args());
  assert.equal(output.code, 0, output.stdout);
  assert.deepEqual(JSON.parse(requests()[0]!.body), {
    name: "by-status",
    type: "terms",
    field: "status",
  });
  assert.match(output.stdout, /0 identity sensor aggregates/);
});

test("identity sensor aggregate refuses a result without buckets", async () => {
  recordedResponse("GetSensorAggregates", 200, { resources: [{ name: "x" }] });
  const output = await run(args());
  assert.equal(output.code, 1, output.stdout);
  assert.equal(value(output.stdout).code, "UPSTREAM_ERROR");
});

test("identity sensor aggregate names the missing scope", async () => {
  recordedResponse("GetSensorAggregates", 403, {
    errors: [{ code: 403, message: "access denied" }],
  });
  const output = await run(args());
  assert.equal(output.code, 1, output.stdout);
  assert.equal(value(output.stdout).code, "SCOPE_DENIED");
  assert.match(output.stdout, /Identity Protection Entities:read/);
});

for (const missing of ["--name", "--type", "--field"])
  test(`identity sensor aggregate requires ${missing} before any request`, async () => {
    const all = args();
    const index = all.indexOf(missing);
    const output = await run(
      all.filter((_, i) => i !== index && i !== index + 1),
    );
    assert.equal(output.code, 2, output.stdout);
    assert.equal(value(output.stdout).code, "VALIDATION_ERROR");
    assert.equal(wire.length, 0);
  });

for (const size of ["0", "-1", "1.5", "many"])
  test(`identity sensor aggregate refuses --size ${size} before any request`, async () => {
    const output = await run(args("--size", size));
    assert.equal(output.code, 2, output.stdout);
    assert.equal(value(output.stdout).code, "VALIDATION_ERROR");
    assert.equal(wire.length, 0);
  });

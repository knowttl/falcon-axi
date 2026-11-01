/** Maintainer-only rebuild. npm installation and ordinary builds never compile C. */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
const headers = join(process.execPath, "../../include/node");
const headerPins: Record<string, string> = {
  "node_api.h":
    "2d4560831e525b47b060ec8a0864ab73993df9e20215ce9f0fe7b24cd31af32a",
  "node_api_types.h":
    "088766b3cf1f0cd9b292c361ad30f7a04e7cc6db35a20ca52c572c1adf9635e7",
  "js_native_api.h":
    "eb03b6c850a1cfb593fd03e9e4251db8c82e9a6d9705bca91ac8d1a01fd7037c",
  "js_native_api_types.h":
    "7dd3663630849ada3a30d39abf42a192c9b6e7de63017cd32c41f5371a475b34",
};
for (const [name, expected] of Object.entries(headerPins)) {
  if (
    createHash("sha256")
      .update(readFileSync(join(headers, name)))
      .digest("hex") !== expected
  )
    throw new Error(`Pinned Node 24.14.0 header required: ${name}`);
}
const targets = [
  {
    name: "linux-x64.node",
    compiler: "/usr/bin/gcc",
    version: "gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0",
    flags: ["-B/usr/bin/", "-shared", "-fPIC"],
  },
  {
    name: "win32-x64.node",
    compiler: "/usr/bin/x86_64-w64-mingw32-gcc",
    version: "x86_64-w64-mingw32-gcc (GCC) 13-win32",
    flags: ["-shared", "-static-libgcc", "-Wl,--no-insert-timestamp"],
  },
];
const binutils = {
  "/usr/bin/ld": "GNU ld (GNU Binutils for Ubuntu) 2.42",
  "/usr/bin/as": "GNU assembler (GNU Binutils for Ubuntu) 2.42",
  "/usr/bin/x86_64-w64-mingw32-ld": "GNU ld (GNU Binutils) 2.41.90.20240122",
  "/usr/bin/x86_64-w64-mingw32-as":
    "GNU assembler (GNU Binutils) 2.41.90.20240122",
};
for (const [executable, expected] of Object.entries(binutils)) {
  const version = spawnSync(executable, ["--version"], { encoding: "utf8" });
  if (version.status !== 0 || version.stdout.split("\n")[0] !== expected)
    throw new Error(`Pinned native tool required: ${expected}`);
}
mkdirSync(join(root, "native/prebuilds"), { recursive: true });
const checksums: Record<string, string> = {};
for (const target of targets) {
  const version = spawnSync(target.compiler, ["--version"], {
    encoding: "utf8",
  });
  if (version.status !== 0 || version.stdout.split("\n")[0] !== target.version)
    throw new Error(`Pinned native compiler required: ${target.version}`);
  const output = join(root, "native/prebuilds", target.name);
  const result = spawnSync(
    target.compiler,
    [
      "-std=c11",
      "-O2",
      "-Wall",
      "-Wextra",
      "-Werror",
      "-fstack-protector-strong",
      "-I",
      headers,
      ...target.flags,
      "-o",
      output,
      join(root, "native/rtr_fs.c"),
    ],
    { stdio: "inherit" },
  );
  if (result.status !== 0)
    throw new Error(`Native build failed: ${target.name}`);
  checksums[target.name] = createHash("sha256")
    .update(readFileSync(output))
    .digest("hex");
}
writeFileSync(
  join(root, "native/checksums.json"),
  `${JSON.stringify(checksums, null, 2)}\n`,
);
writeFileSync(
  join(root, "native/provenance.json"),
  `${JSON.stringify(
    {
      napi: 8,
      headers: headerPins,
      targets,
      binutils,
      inputs: Object.fromEntries(
        ["native/rtr_fs.c", "scripts/typescript/build-native.ts"].map(
          (path) => [
            path,
            createHash("sha256")
              .update(readFileSync(join(root, path)))
              .digest("hex"),
          ],
        ),
      ),
    },
    null,
    2,
  )}\n`,
);

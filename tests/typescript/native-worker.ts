import assert from "node:assert/strict";
import { connect } from "node:net";
const { openRetainedFile } = (await import(
  process.argv[4] ??
    new URL("../../src/rtr-filesystem.js", import.meta.url).href
)) as typeof import("../../src/rtr-filesystem.js");

const [mode, path] = process.argv.slice(2);
assert.ok(path);
if (mode === "windows") {
  Object.defineProperty(process, "platform", { value: "win32" });
  assert.throws(
    () => openRetainedFile(path),
    /requires a supported POSIX controller/,
  );
} else if (mode === "network-deny") {
  const socket = connect({ host: path, port: 9 });
  socket.once("error", (error: NodeJS.ErrnoException) => {
    assert.equal(error.code, "EPERM");
    socket.destroy();
  });
} else if (mode === "lock") {
  try {
    const lock = openRetainedFile(path, true);
    console.log("acquired");
    lock.close();
  } catch (error) {
    console.log((error as { code: string }).code);
    process.exitCode = 1;
  }
} else {
  const file = openRetainedFile(path);
  try {
    if (mode?.endsWith("flush-failure")) {
      assert.throws(() => file.append(Buffer.from("synthetic intent\n")), {
        code: "CONFIG_INSECURE",
      });
      assert.throws(() => file.append(Buffer.from("must not replay\n")), {
        code: "CONFIG_INSECURE",
      });
    } else {
      file.append(Buffer.from("synthetic intent\n"));
    }
  } finally {
    file.close();
  }
}

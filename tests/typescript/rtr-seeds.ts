import { registerHooks } from "node:module";

const seed = process.env.S11_MUTATION;
registerHooks({
  load(url, context, nextLoad) {
    const result = nextLoad(url, context);
    const target =
      seed === "alias-partition"
        ? "/runner/runner.js"
        : seed === "missing-grant" || seed === "tampered-body"
          ? "/src/transport/https.js"
          : "/src/rtr.js";
    if (!seed || !url.endsWith(target)) return result;
    let source =
      typeof result.source === "string"
        ? result.source
        : Buffer.isBuffer(result.source)
          ? result.source.toString()
          : "";
    const before = source;
    if (seed === "missing-grant")
      source = source.replace("rtr: grant,", "rtr: undefined,");
    if (seed === "tampered-body")
      source = source.replace("body: claim.body,", 'body: claim.body + " ",');
    if (seed === "missing-flush") {
      const start = source.indexOf('record.cleanup = "unknown";');
      const position = source.indexOf("append();", start);
      if (start >= 0 && position >= 0)
        source =
          source.slice(0, position) +
          "void 0;" +
          source.slice(position + "append();".length);
    }
    if (seed === "suppressed-cleanup")
      source = source.replace(
        'await send("RTR_DeleteSession", AbortSignal.timeout(10000));',
        "void 0;",
      );
    if (seed === "alias-partition")
      source = source.replace(
        "acquireFalconRtrLock(this.root, executable, limits.falconRtrDevice)",
        "acquireFalconRtrLock(join(this.root, environment.FALCON_AXI_WRITE_LOG), executable, limits.falconRtrDevice)",
      );
    if (!source || source === before)
      throw new Error(`Mutation did not apply: ${seed}`);
    process.stderr.write(`seed-applied:${seed}\n`);
    return { ...result, source };
  },
});

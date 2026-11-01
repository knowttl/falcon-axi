import { randomUUID } from "node:crypto";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { CliError, object } from "./core.js";
import { authenticate, responseFailure } from "./auth.js";
import { directory, writeLogPath } from "./credentials.js";
import type { Credential } from "./credentials.js";
import { origin } from "./origin.js";
import { redact, render } from "./render.js";
import { openRetainedFile } from "./rtr-filesystem.js";
import {
  catListing,
  commandTokens,
  parseRtr,
  readOnly,
  rtrPolicy,
  validateRtrHost,
} from "./rtr-policy.js";
import type { Invocation } from "./parser.js";
import { operation } from "./transport/operations.js";
import { requestRtr } from "./transport/https.js";

interface Claim {
  readonly origin: string;
  readonly token: string;
  readonly method: string;
  readonly path: string;
  readonly body: string;
  readonly id: string;
  readonly host: string;
  readonly command: string;
  readonly allowed: readonly string[];
}
const grants = new WeakMap<object, Claim>();
// Keep minting private to the authorized lifecycle; the sink can only inspect and consume.
const deny = (): CliError =>
  new CliError(
    "READ_ONLY_VIOLATION",
    "RTR request does not match this run's execution authority",
  );
export function inspectRtrGrant(grant: object): Claim {
  const claim = grants.get(grant);
  if (!claim) throw deny();
  validateRtrHost(claim.host);
  parseRtr(claim.command, claim.allowed);
  origin(claim.origin, false);
  if (claim.id !== "RTR_DeleteSession" && readOnly()) throw deny();
  return claim;
}
export function consumeRtrGrant(
  grant: object,
  prepared: {
    origin: string;
    method: string;
    path: string;
    body: string;
    headers: Readonly<Record<string, string>>;
  },
): void {
  const claim = inspectRtrGrant(grant);
  if (
    prepared.origin !== claim.origin ||
    prepared.method !== claim.method ||
    prepared.path !== claim.path ||
    prepared.body !== claim.body ||
    prepared.headers.authorization !== `Bearer ${claim.token}`
  )
    throw deny();
  grants.delete(grant);
}
function resource(body: unknown): Record<string, unknown> {
  if (
    !object(body) ||
    !Array.isArray(body.resources) ||
    body.resources.length !== 1 ||
    !object(body.resources[0])
  )
    throw new CliError(
      "UPSTREAM_ERROR",
      "RTR response did not identify one resource",
    );
  return body.resources[0];
}
function identifier(row: Record<string, unknown>, key: string): string {
  const value = row[key];
  if (
    typeof value !== "string" ||
    !value ||
    value.length > 256 ||
    /[\x00-\x20]/.test(value)
  )
    throw new CliError(
      "UPSTREAM_ERROR",
      "RTR response omitted a valid lifecycle identifier",
    );
  return value;
}
function fileSize(output: string, command: string): number | undefined {
  const path = commandTokens(command)[1]!.replace(/^["']|["']$/g, "");
  const names = new Set([path, path.replaceAll("\\", "/").split("/").at(-1)!]);
  const lines = output
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const headers = lines.flatMap((line, index) =>
    /^Name\s+Type\s+Size \(bytes\)/.test(line) ? [index] : [],
  );
  if (headers.length !== 1) return;
  const rows = lines.slice(headers[0]! + 1).flatMap((line) => {
    const name = [...names]
      .sort((a, b) => b.length - a.length)
      .find(
        (name) => line.startsWith(name) && /^\s/.test(line.slice(name.length)),
      );
    return name ? [line.slice(name.length).trim()] : [];
  });
  if (rows.length !== 1) return;
  const match = /^\.[^\s]+\s+([0-9]+)(?:\s+.*)?$/.exec(rows[0]!);
  const size = match ? Number(match[1]) : NaN;
  return Number.isSafeInteger(size) ? size : undefined;
}

export function validateRtrInvocation(invocation: Invocation): {
  host: string;
  command: string;
  executing: boolean;
} {
  const { flags } = invocation;
  const host = invocation.id!;
  const command = flags.get("--command");
  if (command === undefined)
    throw new CliError(
      "VALIDATION_ERROR",
      "rtr run requires --command '<complete command>'",
    );
  validateRtrHost(host);
  const executing = flags.has("--execute");
  if (executing && readOnly())
    throw new CliError(
      "READ_ONLY_VIOLATION",
      "FALCON_AXI_READ_ONLY forbids RTR execution",
    );
  if (flags.has("--confirm") && !executing)
    throw new CliError("VALIDATION_ERROR", "--confirm requires --execute");
  if (executing && flags.get("--confirm") !== `${host}:${command}`)
    throw new CliError(
      "VALIDATION_ERROR",
      "--confirm must match '<device_id>:<complete command>' exactly",
    );
  return { host, command, executing };
}
export async function rtrRun(
  invocation: Invocation,
  credential: Credential,
  base: string,
  cancelled: AbortSignal,
): Promise<void> {
  const { host, command, executing } = validateRtrInvocation(invocation);
  origin(base, false);
  const policy = credential.rtr ?? rtrPolicy(undefined);
  const commandBase = parseRtr(command, policy.commands);
  if (executing && (credential.channel !== "file" || !policy.enabled))
    throw new CliError(
      "READ_ONLY_VIOLATION",
      "RTR execution requires explicit profile opt-in",
    );
  if (executing && (process.platform !== "linux" || process.arch !== "x64"))
    throw new CliError(
      "CONFIG_INSECURE",
      "RTR execution requires a supported POSIX controller",
    );
  process.stdout.write(
    render(
      {
        preview: {
          host,
          command,
          profile: credential.profile,
          origin: base,
          enabled: policy.enabled,
          allowed_commands: [...policy.commands].sort(),
          execution_seconds: 50,
          cleanup_seconds: 10,
          output_bytes: 65536,
          output_chunks: 64,
          journal: writeLogPath(),
          session_deletion: "mandatory",
        },
      },
      executing
        ? []
        : [
            "Execution requires profile rtr.enabled=true and both --execute and --confirm '<device_id>:<complete command>'; FALCON_AXI_READ_ONLY always wins",
          ],
    ),
  );
  if (!executing) return;
  const lock = openRetainedFile(
    join(directory("state"), `rtr-${host.toLowerCase()}.lock`),
    true,
  );
  try {
    const journal = openRetainedFile(writeLogPath());
    try {
      await executeLocked(
        host,
        command,
        commandBase,
        policy.commands,
        credential,
        base,
        journal,
        cancelled,
      );
    } finally {
      journal.close();
    }
  } finally {
    lock.close();
  }
}

async function executeLocked(
  host: string,
  command: string,
  commandBase: string,
  allowed: readonly string[],
  credential: Credential,
  base: string,
  journal: ReturnType<typeof openRetainedFile>,
  cancelled: AbortSignal,
): Promise<void> {
  const run = randomUUID().replaceAll("-", "");
  const record: Record<string, unknown> = {
    run,
    target: host,
    command,
    authorization: "allowed",
    phase: "intent",
    command_outcome: "not_started",
    cleanup: "not_needed",
  };
  const append = (): void =>
    journal.append(
      Buffer.from(
        JSON.stringify(
          redact({ ...record, timestamp: new Date().toISOString() }),
        ) + "\n",
      ),
    );
  append();
  const execution = AbortSignal.any([cancelled, AbortSignal.timeout(50000)]);
  let destination = base;
  let token = "";
  let session: string | undefined;
  let requestId: string | undefined;
  let initialized = false;
  let executed = false;
  let sizeChecked = false;
  let deleted = false;
  let requests = 0;
  let rawOutput = "";
  let output = "";
  let complete = false;
  let truncated = false;
  let size: number | undefined;
  let stdoutBytes = 0;
  let hasStderr = false;
  let failure: CliError | undefined;
  const listing = catListing(command, allowed);
  const send = async (
    id: string,
    signal: AbortSignal,
    sequence = 0,
  ): Promise<unknown> => {
    if (id !== "RTR_DeleteSession" && readOnly()) throw deny();
    signal.throwIfAborted();
    validateRtrHost(host);
    parseRtr(command, allowed);
    let body: unknown;
    const query = new URLSearchParams();
    if (id === "RTR_InitSession") {
      if (initialized) throw deny();
      initialized = true;
      body = { device_id: host, queue_offline: false };
    } else if (id === "RTR_ExecuteCommand") {
      if (!session || deleted || executed) throw deny();
      const derived = listing !== undefined && !sizeChecked;
      body = {
        base_command: derived ? "ls" : commandBase,
        command_string: derived ? listing : command,
        session_id: session,
      };
      if (derived) sizeChecked = true;
      else executed = true;
    } else if (id === "RTR_CheckCommandStatus") {
      if (
        !requestId ||
        deleted ||
        !(executed || sizeChecked) ||
        requests >= 64 ||
        !Number.isSafeInteger(sequence) ||
        sequence < 0
      )
        throw deny();
      requests++;
      query.set("cloud_request_id", requestId);
      query.set("sequence_id", String(sequence));
    } else if (id === "RTR_DeleteSession") {
      if (!session || deleted) throw deny();
      deleted = true;
      query.set("session_id", session);
    } else throw deny();
    const descriptor = operation(id);
    const grant = Object.freeze({});
    grants.set(
      grant,
      Object.freeze({
        id,
        host,
        command,
        allowed,
        origin: origin(destination, false),
        token,
        method: descriptor.method,
        path: descriptor.path + (query.size ? `?${query}` : ""),
        body: body === undefined ? "" : JSON.stringify(body),
      }),
    );
    try {
      const response = await requestRtr(grant, signal);
      if (
        id === "RTR_ExecuteCommand" &&
        response.status === 400 &&
        object(response.body) &&
        Array.isArray(response.body.errors) &&
        response.body.errors.some(
          (error: unknown) =>
            object(error) &&
            typeof error.message === "string" &&
            /command not found/i.test(error.message),
        )
      )
        throw new CliError(
          "UPSTREAM_ERROR",
          `Falcon does not accept the RTR command ${commandBase}`,
          [
            "The command may not exist on this host's platform, or only in the interactive RTR console",
            "Run `falcon-axi rtr run --help` for the commands and the platforms they were verified on",
          ],
        );
      if (response.status < 200 || response.status >= 300)
        responseFailure(response, "RTR lifecycle", false, false, id);
      return response.body;
    } finally {
      grants.delete(grant);
    }
  };
  const chunks = async function* (): AsyncGenerator<{
    stdout: string;
    stderr: string;
    ended: boolean;
  }> {
    let sequence = 0;
    while (requests < 64) {
      const row = resource(
        await send("RTR_CheckCommandStatus", execution, sequence),
      );
      const stdout = row.stdout ?? "",
        stderr = row.stderr ?? "";
      if (
        typeof stdout !== "string" ||
        typeof stderr !== "string" ||
        typeof row.complete !== "boolean"
      )
        throw new CliError(
          "UPSTREAM_ERROR",
          "RTR returned malformed command output",
        );
      const cursor =
        row.sequence_id === undefined && row.complete
          ? sequence
          : row.sequence_id;
      if (
        typeof cursor !== "number" ||
        !Number.isSafeInteger(cursor) ||
        cursor < sequence
      )
        throw new CliError(
          "UPSTREAM_ERROR",
          "RTR returned an invalid output sequence",
        );
      sequence = row.complete ? Math.max(sequence + 1, cursor) : cursor;
      yield { stdout, stderr, ended: row.complete };
      if (row.complete && !stdout && !stderr) return;
      if (!row.complete) await delay(100, undefined, { signal: execution });
    }
  };
  try {
    record.phase = "authentication";
    const authenticated = await authenticate(
      credential,
      base,
      false,
      execution,
    );
    destination = authenticated.base;
    token = authenticated.token;
    record.phase = "init";
    record.cleanup = "unknown";
    append();
    session = identifier(
      resource(await send("RTR_InitSession", execution)),
      "session_id",
    );
    record.session = session;
    record.phase = "execute";
    record.cleanup = "pending";
    append();
    if (listing !== undefined) {
      try {
        requestId = identifier(
          resource(await send("RTR_ExecuteCommand", execution)),
          "cloud_request_id",
        );
        let text = "";
        for await (const chunk of chunks()) {
          if (chunk.stderr) break;
          text += chunk.stdout;
          if (Buffer.byteLength(text) > 65536) break;
          if (chunk.ended && !chunk.stdout) {
            size = fileSize(text, command);
            break;
          }
        }
      } catch (error) {
        if (
          execution.aborted ||
          !(error instanceof CliError) ||
          error.code === "WAIT_TIMEOUT"
        )
          throw error;
      }
    }
    requestId = identifier(
      resource(await send("RTR_ExecuteCommand", execution)),
      "cloud_request_id",
    );
    record.phase = "status";
    record.command_outcome = "unknown";
    for await (const chunk of chunks()) {
      rawOutput += chunk.stdout + chunk.stderr;
      stdoutBytes += Buffer.byteLength(chunk.stdout);
      hasStderr ||= Boolean(chunk.stderr);
      const safe = Buffer.from(String(redact(rawOutput)));
      output = new TextDecoder("utf-8", { ignoreBOM: true }).decode(
        safe.subarray(0, 65536),
        { stream: true },
      );
      if (Buffer.byteLength(rawOutput) > 65536 || safe.length >= 65536) {
        truncated = true;
        break;
      }
      if (chunk.ended && !chunk.stdout && !chunk.stderr) {
        complete = true;
        break;
      }
    }
    if (!complete) truncated = true;
  } catch (error) {
    failure =
      error instanceof CliError
        ? error
        : new CliError(
            execution.aborted ? "WAIT_TIMEOUT" : "UPSTREAM_ERROR",
            execution.aborted
              ? "RTR execution interrupted or exceeded its time budget"
              : "RTR execution failed",
          );
    record.command_outcome = executed ? "unknown" : "not_started";
  } finally {
    if (commandBase === "cat") {
      if (size !== undefined)
        truncated ||=
          Math.min(stdoutBytes, Buffer.byteLength(output)) < size ||
          size >= 65536;
      complete =
        complete &&
        size !== undefined &&
        !truncated &&
        !hasStderr &&
        Buffer.byteLength(output) === size &&
        stdoutBytes === size;
    }
    if (!failure) record.command_outcome = complete ? "complete" : "incomplete";
    if (session) {
      record.phase = "delete";
      try {
        await send("RTR_DeleteSession", AbortSignal.timeout(10000));
        record.cleanup = "deleted";
      } catch {
        record.cleanup = "failed";
        failure = new CliError(
          "UPSTREAM_ERROR",
          "RTR session deletion could not be confirmed",
        );
      }
    }
    record.phase = "outcome";
    try {
      append();
    } catch (error) {
      const journalError =
        error instanceof CliError
          ? error
          : new CliError(
              "CONFIG_INSECURE",
              "RTR journal could not be durably written",
            );
      failure ??= journalError;
      failure.details.journal_error = {
        code: journalError.code,
        message: journalError.message,
      };
    }
  }
  const result = {
    run_id: run,
    output,
    complete,
    truncated,
    cleanup: record.cleanup,
    size_unverified: commandBase === "cat" && size === undefined,
  };
  if (failure) {
    Object.assign(failure.details, {
      run,
      output,
      complete,
      truncated,
      cleanup: record.cleanup,
      ...(commandBase === "cat" ? { size_unverified: size === undefined } : {}),
      command_outcome: record.command_outcome,
    });
    if (record.cleanup === "unknown")
      throw new CliError(
        failure.code,
        failure.message,
        [
          ...failure.help,
          "Reconcile the host's sessions in Falcon before retrying; never replay initialization automatically",
        ],
        failure.details,
      );
    throw failure;
  }
  process.stdout.write(render({ result }));
}

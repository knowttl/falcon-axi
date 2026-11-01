import ts from "typescript";
import { readFileSync, readdirSync } from "node:fs";
import { resolve, relative, join } from "node:path";

const root = resolve("src");
const allowed = new Set([
  "node:fs",
  "node:fs/promises",
  "node:path",
  "node:os",
  "node:crypto",
  "./core.js",
  "./credentials.js",
  "./auth.js",
  "./origin.js",
  "./render.js",
  "./response.js",
  "./metadata.js",
  "./investigation.js",
  "./domain.js",
  "./inventory.js",
  "./exposure.js",
  "./inspection.js",
  "./inspection-commands.json",
  "./parser.js",
  "./cursor.js",
  "./windows-acl.js",
  "./help.json",
  "./version.js",
  "./cli.js",
  "./transport/https.js",
  "./operations.js",
  "./descriptors.json",
  "./axi-credential.schema.json",
  "../core.js",
  "../origin.js",
  "../version.js",
  "./transport/operations.js",
  "@toon-format/toon",
  "axi-sdk-js/fast-path",
  "ajv/dist/2020.js",
]);
const sink = new Set([
  "node:https",
  "node:http",
  "node:tls",
  "node:stream",
  "node:timers/promises",
  "./resolver.js",
]);
export function violations(source: string, name: string): string[] {
  const file = ts.createSourceFile(name, source, ts.ScriptTarget.Latest, true);
  const errors: string[] = [];
  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) {
      const specifier = node.moduleSpecifier;
      if (
        specifier &&
        (!ts.isStringLiteral(specifier) ||
          !(
            allowed.has(specifier.text) ||
            (name === "transport/https.ts" && sink.has(specifier.text)) ||
            (name === "transport/resolver.ts" &&
              [
                "node:child_process",
                "node:net",
                "node:dns",
                "node:url",
              ].includes(specifier.text)) ||
            (name === "transport/dns-worker.ts" &&
              specifier.text === "node:dns/promises") ||
            (name === "windows-acl.ts" &&
              specifier.text === "node:child_process") ||
            (name === "rtr-filesystem.ts" &&
              ["node:module", "node:url", "../native/checksums.json"].includes(
                specifier.text,
              ))
          ))
      )
        errors.push("unauthorized dependency");
    }
    if (ts.isCallExpression(node)) {
      const expression = node.expression;
      const nameText = expression.getText(file);
      if (expression.kind === ts.SyntaxKind.ImportKeyword) {
        if (
          name !== "bin.ts" ||
          node.arguments.length !== 1 ||
          !ts.isStringLiteral(node.arguments[0]!) ||
          node.arguments[0]!.text !== "./cli.js"
        )
          errors.push("dynamic import authority");
      } else if (
        /require|eval|Function|fetch|constructor|process\.(?:binding|dlopen|getBuiltinModule)|importScripts/.test(
          nameText,
        )
      )
        errors.push("indirect authority");
    }
    if (
      ts.isIdentifier(node) &&
      [
        "globalThis",
        "global",
        "WebSocket",
        "XMLHttpRequest",
        "Worker",
        "Deno",
        "Bun",
        "module",
        "require",
        "eval",
        "Function",
        "constructor",
        "getBuiltinModule",
        "binding",
        "dlopen",
      ].includes(node.text)
    )
      errors.push("ambient authority");
    ts.forEachChild(node, visit);
  };
  visit(file);
  return errors;
}
function walk(directory: string): void {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) walk(path);
    else if (entry.name.endsWith(".ts")) {
      const problems = violations(
        readFileSync(path, "utf8"),
        relative(root, path),
      );
      if (problems.length) throw new Error(`${path}: ${problems.join(", ")}`);
    }
  }
}
walk(root);
// Compile representative bypass seeds through the same checker.
for (const source of [
  "import https from 'node:https'",
  "import x from 'undici'",
  "import {spawn} from 'node:child_process'",
  "import fs from 'node:fs'; fs.constructor.constructor('return process')()",
  "const x = globalThis['fetch']; x('url')",
  "await import('node:http')",
  "process.getBuiltinModule('net')",
]) {
  if (!violations(source, "seed.ts").length)
    throw new Error("Architecture checker accepted a bypass seed");
}
console.log("TypeScript architecture boundary and bypass seeds passed");

import { execFileSync } from "node:child_process";
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
} from "node:fs";
import { dirname, join, relative } from "node:path";

export function installPacked(
  checkout: string,
  tarball: string,
  prefix: string,
): void {
  const modules = join(prefix, "node_modules");
  const unpacked = mkdtempSync(join(prefix, "unpacked-"));
  execFileSync("tar", ["-xzf", tarball, "-C", unpacked]);
  const manifest = JSON.parse(
    readFileSync(join(unpacked, "package", "package.json"), "utf8"),
  ) as { name: string; bin: Record<string, string>; dependencies: object };
  const installed = join(modules, manifest.name);
  mkdirSync(dirname(installed), { recursive: true });
  renameSync(join(unpacked, "package"), installed);
  rmSync(unpacked, { recursive: true });
  for (const dependency of Object.keys(manifest.dependencies)) {
    mkdirSync(dirname(join(modules, dependency)), { recursive: true });
    symlinkSync(
      join(checkout, "node_modules", dependency),
      join(modules, dependency),
    );
  }
  mkdirSync(join(modules, ".bin"));
  for (const [command, path] of Object.entries(manifest.bin)) {
    chmodSync(join(installed, path), 0o755);
    symlinkSync(
      relative(join(modules, ".bin"), join(installed, path)),
      join(modules, ".bin", command),
    );
  }
}

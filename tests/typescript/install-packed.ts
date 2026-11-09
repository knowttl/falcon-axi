import { execFileSync } from "node:child_process";
import {
  chmodSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
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
  const copied = new Map<string, string>();
  function copyDependency(
    from: string,
    name: string,
    optional = false,
  ): string | undefined {
    let directory = from;
    let source: string;
    while (true) {
      source = join(directory, "node_modules", name);
      if (existsSync(source)) break;
      const parent = dirname(directory);
      if (parent === directory) {
        if (optional) return undefined;
        throw new Error(`Missing installed dependency: ${name}`);
      }
      directory = parent;
    }
    source = realpathSync(source);
    const existing = copied.get(source);
    if (existing) return existing;
    const destination = join(
      modules,
      ".store",
      String(copied.size),
      "node_modules",
      name,
    );
    copied.set(source, destination);
    mkdirSync(dirname(destination), { recursive: true });
    cpSync(source, destination, {
      recursive: true,
      dereference: true,
      filter: (path) => path !== join(source, "node_modules"),
    });
    const packageManifest = JSON.parse(
      readFileSync(join(source, "package.json"), "utf8"),
    ) as {
      dependencies?: Record<string, string>;
      optionalDependencies?: Record<string, string>;
      peerDependencies?: Record<string, string>;
    };
    const optionalNames = new Set(
      Object.keys(packageManifest.optionalDependencies ?? {}),
    );
    for (const child of Object.keys({
      ...packageManifest.dependencies,
      ...packageManifest.optionalDependencies,
      ...packageManifest.peerDependencies,
    })) {
      const target = copyDependency(
        source,
        child,
        optionalNames.has(child) ||
          child in (packageManifest.peerDependencies ?? {}),
      );
      if (target) {
        const link = join(destination, "node_modules", child);
        mkdirSync(dirname(link), { recursive: true });
        symlinkSync(relative(dirname(link), target), link);
      }
    }
    return destination;
  }
  for (const dependency of Object.keys(manifest.dependencies)) {
    const link = join(modules, dependency);
    mkdirSync(dirname(link), { recursive: true });
    symlinkSync(
      relative(dirname(link), copyDependency(checkout, dependency)!),
      link,
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

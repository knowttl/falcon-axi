import { statSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { homedir } from "node:os";

export const HOME_GUIDANCE = [
  "Run `falcon-axi detection list` to see more detections",
  "Run `falcon-axi detection list --product idp` for Identity Protection detections",
  "Run `falcon-axi host list --filter \"hostname:'WIN-*'\"` to search hosts",
  "Run `falcon-axi cve show <CVE-ID>` for Falcon Intelligence on one CVE",
  "Run `falcon-axi scopes` to see what this API client needs",
] as const;

export function skillHint(): string[] {
  const env = process.env;
  const host = env.CLAUDECODE
    ? "claude"
    : env.CODEX_THREAD_ID || env.CODEX_SESSION_ID
      ? "codex"
      : env.PI_CODING_AGENT
        ? "pi"
        : env.OPENCODE
          ? "opencode"
          : undefined;
  if (!host) return [];
  try {
    const home = env.HOME || homedir();
    const agents = ".agents/skills";
    const claude = ".claude/skills";
    const roots =
      host === "claude"
        ? [join(env.CLAUDE_CONFIG_DIR || join(home, ".claude"), "skills")]
        : host === "codex"
          ? [join(home, agents)]
          : host === "pi"
            ? [
                join(
                  env.PI_CODING_AGENT_DIR || join(home, ".pi/agent"),
                  "skills",
                ),
                join(home, agents),
              ]
            : [
                join(
                  env.XDG_CONFIG_HOME || join(home, ".config"),
                  "opencode/skills",
                ),
                join(home, claude),
                join(home, agents),
              ];
    const projects =
      host === "claude"
        ? [claude]
        : host === "codex"
          ? [agents]
          : host === "pi"
            ? [".pi/skills", agents]
            : [".opencode/skills", claude, agents];
    const stat = (path: string): ReturnType<typeof statSync> | undefined => {
      try {
        return statSync(path);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT")
          return undefined;
        throw error;
      }
    };
    for (let directory = process.cwd(); ; directory = dirname(directory)) {
      roots.push(...projects.map((project) => join(directory, project)));
      const git = join(directory, ".git");
      const metadata = stat(git);
      if (metadata) {
        if (host === "claude" && metadata.isFile()) {
          const pointer = readFileSync(git, "utf8").trim();
          if (pointer.startsWith("gitdir:")) {
            const gitdir = resolve(directory, pointer.slice(7).trim());
            if (dirname(gitdir).endsWith("/worktrees"))
              roots.push(join(dirname(dirname(dirname(gitdir))), claude));
          }
        }
        break;
      }
      if (directory === dirname(directory)) break;
    }
    return roots.some((root) =>
      stat(join(root, "falcon-axi/SKILL.md"))?.isFile(),
    )
      ? []
      : [
          "Run `npx skills add knowttl/falcon-axi --skill falcon-axi` to install the falcon-axi skill",
        ];
  } catch {
    // Best-effort discovery must never alter the command's result.
    return [];
  }
}

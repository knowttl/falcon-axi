import { execFile } from "node:child_process";

// Fixed source; the selected path is child environment data, never PowerShell source.
const metadataScript = `
$ErrorActionPreference = 'Stop'
$item = Get-Item -LiteralPath $env:FALCON_AXI_ACL_PATH -Force
while ($null -ne $item) {
  if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { exit 1 }
  $item = if ($item -is [IO.FileInfo]) { $item.Directory } else { $item.Parent }
}
`;
const aclScript = `
$acl = Get-Acl -LiteralPath $env:FALCON_AXI_ACL_PATH
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$allowed = @($user, 'S-1-5-18', 'S-1-5-32-544')
if (-not $acl.AreAccessRulesProtected) { exit 1 }
$seen = @()
foreach ($rule in $acl.Access) {
  $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
  if ($sid -notin $allowed -or $rule.IsInherited -or
      $rule.AccessControlType -ne 'Allow' -or
      $rule.FileSystemRights -ne [System.Security.AccessControl.FileSystemRights]::FullControl) { exit 1 }
  $seen += $sid
}
foreach ($sid in $allowed) { if ($sid -notin $seen) { exit 1 } }
`;
export function verifyWindowsFile(
  path: string,
  diagnostic: boolean,
): Promise<boolean> {
  return new Promise((resolve) => {
    execFile(
      "powershell.exe",
      [
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        diagnostic ? metadataScript + aclScript : metadataScript,
      ],
      {
        env: { ...process.env, FALCON_AXI_ACL_PATH: path },
        timeout: 10000,
        windowsHide: true,
        maxBuffer: 65536,
      },
      (error) => resolve(error === null),
    );
  });
}

"""Private reads and the Windows diagnostic DACL check.

This reader never writes configuration or persists credentials.
"""

import os
import stat
import subprocess
from collections.abc import Callable

from falcon_axi.core import CliError

# Fixed source; the path is child environment data, never PowerShell source.
ACL_SCRIPT = """
$ErrorActionPreference = 'Stop'
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
"""


def verify_windows_acl(path: str) -> bool:
    try:
        result = subprocess.run(  # noqa: S603
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ACL_SCRIPT],  # noqa: S607
            env={**os.environ, "FALCON_AXI_ACL_PATH": path},
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def read_private_file(
    path: str,
    *,
    secret: bool = False,
    diagnostic: bool = False,
    platform: str | None = None,
    acl: Callable[[str], bool] = verify_windows_acl,
) -> str | None:
    """Check provenance before reading; missing files are distinct from unsafe ones."""
    windows = (os.name if platform is None else platform) == "nt"
    fix = f"Apply a protected owner/SYSTEM/Administrators DACL to {path}" if windows else f"Run `chmod 600 {path}`"
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise CliError("CONFIG_INSECURE", f"cannot inspect {path}", [fix]) from error
    unsafe = not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
    if windows:
        unsafe |= bool(getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)
        if not unsafe and diagnostic:
            unsafe = not acl(path)
    else:
        unsafe |= info.st_uid != os.getuid() or bool(info.st_mode & (0o077 if secret else 0o022))
    if unsafe:
        raise CliError("CONFIG_INSECURE", f"the file at {path} is not protected", [fix, "Replace links with a regular file"])
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, encoding="utf-8-sig") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise CliError("CONFIG_INSECURE", f"the file at {path} changed during its read check", [fix])
            return stream.read()
    except (OSError, UnicodeError) as error:
        raise CliError("CONFIG_INVALID", f"cannot read UTF-8 from {path}") from error

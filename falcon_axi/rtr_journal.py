"""Private append-only, durably flushed N3 intent and outcome records."""

import json
import os
import stat
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from falcon_axi.core import CliError
from falcon_axi.redaction import redact_text


class Journal:
    def __init__(self, path: str) -> None:
        self.path = Path(path)

    def append(self, record: Mapping[str, Any]) -> None:
        descriptor = -1
        directory = -1
        try:
            if not self.path.is_absolute() or os.name != "posix":
                raise OSError("journal requires a private absolute POSIX path")
            # Traverse using directory descriptors, refusing symlinks in every component.
            directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
            for part in self.path.parent.parts[1:]:
                try:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                except FileNotFoundError:
                    os.mkdir(part, mode=0o700, dir_fd=directory)
                    os.fsync(directory)
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                os.close(directory)
                directory = child
            parent = os.fstat(directory)
            if parent.st_uid != os.getuid() or parent.st_mode & 0o022:
                raise OSError("unsafe journal directory")
            descriptor = os.open(
                self.path.name,
                os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                0o600,
                dir_fd=directory,
            )
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise OSError("unsafe journal file")
            data = (redact_text(json.dumps({"timestamp": datetime.now(UTC).isoformat(), **record})) + "\n").encode()
            with os.fdopen(descriptor, "ab") as stream:
                descriptor = -1
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(directory)
        except OSError as error:
            raise CliError("CONFIG_INSECURE", "RTR journal could not be durably written") from error
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if directory >= 0:
                os.close(directory)

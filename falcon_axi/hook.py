"""Fail-open session context, resolved entirely from local configuration."""

import os

from falcon_axi.core import CliError
from falcon_axi.credentials import resolve_credential
from falcon_axi.origin import assert_trusted_origin, resolve_base_url
from falcon_axi.redaction import redact_text, redaction_scope
from falcon_axi.version import VERSION


def main() -> int:
    with redaction_scope():
        try:
            credential = resolve_credential(os.environ)
            region = resolve_base_url(region=credential.region)
            assert_trusted_origin(region, False)
            line = f"falcon-axi {VERSION}: profile resolved; region {region}. Run `falcon-axi` for recent detections."
        except Exception as error:
            code = error.code if isinstance(error, CliError) else "LOCAL_STATUS_UNAVAILABLE"
            line = f"falcon-axi {VERSION}: profile unresolved ({code}). Run `falcon-axi setup` for guidance."
        print(redact_text(line).replace("\n", " ").replace("\r", " "))
    return 0

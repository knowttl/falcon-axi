import sys

from falcon_axi.version import version_output

if __name__ == "__main__":
    version = version_output(sys.argv[1:])
    if version is not None:
        sys.stdout.write(version)
    else:
        from falcon_axi.cli import main

        raise SystemExit(main())

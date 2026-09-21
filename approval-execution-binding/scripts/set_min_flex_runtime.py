#!/usr/bin/env python3
"""Set the fail-closed Flex minimum in PDK implementation metadata."""

from __future__ import annotations

from pathlib import Path
import sys

MIN_RUNTIME = "1.14.0"
METADATA_FILES = (
    Path("target/implementation/metadata.yaml"),
    Path("target/implementation-dev/metadata.yaml"),
)


def main() -> int:
    for path in METADATA_FILES:
        if not path.is_file():
            print(f"missing generated implementation metadata: {path}", file=sys.stderr)
            return 1
        lines = path.read_text(encoding="utf-8").splitlines()
        matches = [i for i, line in enumerate(lines) if line.startswith("minRuntimeVersion:")]
        if len(matches) != 1:
            print(f"expected one minRuntimeVersion entry in {path}", file=sys.stderr)
            return 1
        lines[matches[0]] = f"minRuntimeVersion: {MIN_RUNTIME}"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

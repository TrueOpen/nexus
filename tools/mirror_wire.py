#!/usr/bin/env python3
"""Mirror the Node public wire proto of TrueOpen/wire into this repository (Implementation Design §2.1, generated-artifact discipline).

Usage:
    python3 tools/mirror_wire.py            # use the wire version pinned in go.mod
    python3 tools/mirror_wire.py <wire directory>

Mirroring rules (field-for-field identical to wire, dropping only what nexus does not need and should not carry):
  - go_package is rewritten to this repository's path;
  - the gogoproto / cosmos_proto / amino / cosmos.msg / rest_encoding /
    google.api imports and options, which serve only the node and the REST gateway, are dropped. Field numbers, types and
    message/enum/rpc definitions are left untouched;
  - rest_encoding.proto only defines the option being dropped, so it is not mirrored.

After changing proto files run `make proto` as usual; whether the node mirror is correct is decided by the
descriptor fingerprint in internal/chaincli/node_descriptor_test.go.
"""
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PACKAGES = {
    # wire package -> (this repository's go_package, the module it is generated into)
    "hub": "github.com/TrueOpen/nexus/gen/trueopen/hub/v1;hubv1",
    "task": "github.com/TrueOpen/nexus/gen/trueopen/task/v1;taskv1",
    "shared": "github.com/TrueOpen/nexus/gen/trueopen/shared/v1;sharedv1",
    "bus": "github.com/TrueOpen/nexus/gen/bus/v1;busv1",
}
SKIP_FILES = {"shared/v1/rest_encoding.proto"}
DROP_IMPORTS = {
    "gogoproto/gogo.proto",
    "cosmos_proto/cosmos.proto",
    "amino/amino.proto",
    "cosmos/msg/v1/msg.proto",
    "shared/v1/rest_encoding.proto",
    "google/api/annotations.proto",
}
DROP_OPTION_PREFIXES = (
    "(gogoproto.", "(cosmos_proto.", "(amino.", "(cosmos.msg.", "(google.api.", "(shared.v1.rest_",
)


def wire_dir() -> pathlib.Path:
    if len(sys.argv) > 1:
        return pathlib.Path(sys.argv[1])
    out = subprocess.check_output(
        ["go", "list", "-m", "-f", "{{.Dir}}", "github.com/TrueOpen/wire"], cwd=ROOT, text=True
    )
    return pathlib.Path(out.strip())


def strip_field_options(text: str) -> str:
    # The trailing `[ ... ]` of a field: in wire it only holds the option classes listed above, so drop the whole block; it may span lines.
    def repl(match: re.Match) -> str:
        head, body = match.group(1), match.group(2)
        kept = [
            part.strip()
            for part in re.split(r",(?![^(]*\))", body)
            if part.strip() and not part.strip().startswith(DROP_OPTION_PREFIXES)
        ]
        return f"{head} [{', '.join(kept)}]" if kept else head

    # Match only the brackets at the end of a field declaration (after `= <field number>`); `[0]` and `[]` inside comments are left alone.
    return re.sub(r"(=\s*\d+)\s*\[((?:[^\[\]]|\n)*?)\]", repl, text)


def strip_statement_options(text: str) -> str:
    # Drop the multi-line `option (google.api.http) = { ... };` as a whole first, then the single-line options.
    text = re.sub(r"^[ \t]*option \(google\.api\.http\) = \{.*?\};\n", "", text, flags=re.M | re.S)
    text = re.sub(r"^[ \t]*option \((?:gogoproto|cosmos_proto|amino|cosmos\.msg|google\.api)[^\n]*\n", "", text, flags=re.M)
    # rpc X(...) returns (...) { option (google.api.http)...; }  →  rpc X(...) returns (...);
    text = re.sub(r"(returns \([A-Za-z0-9_.]+\))\s*\{\s*\}", r"\1;", text)
    return text


def mirror_file(src: pathlib.Path, rel: str, go_package: str) -> str:
    text = src.read_text()
    lines = []
    for line in text.splitlines(keepends=True):
        m = re.match(r'import "([^"]+)";', line.strip())
        if m and m.group(1) in DROP_IMPORTS:
            continue
        if line.startswith("option go_package"):
            line = f'option go_package = "{go_package}";\n'
        lines.append(line)
    text = "".join(lines)
    text = strip_statement_options(text)
    text = strip_field_options(text)
    # Remove the blank line left behind by deleting a message-level option (a `{` immediately followed by a blank line).
    text = re.sub(r"\{\n\n", "{\n", text)
    return text


def main() -> None:
    src_root = wire_dir() / "proto"
    for pkg, go_package in PACKAGES.items():
        dst_dir = ROOT / "proto" / pkg / "v1"
        for old in dst_dir.glob("*.proto"):
            old.unlink()
        dst_dir.mkdir(parents=True, exist_ok=True)
        for src in sorted((src_root / pkg / "v1").glob("*.proto")):
            rel = f"{pkg}/v1/{src.name}"
            if rel in SKIP_FILES:
                continue
            (dst_dir / src.name).write_text(mirror_file(src, rel, go_package))
            print(f"  {rel}")


if __name__ == "__main__":
    main()

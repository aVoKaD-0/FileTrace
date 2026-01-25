import re


_SUPPRESSED_PREFIXES = (
    "docker build stdout:",
    "docker build stderr:",
    "docker run stdout:",
    "docker run stderr:",
)

_SUPPRESSED_PREFIXES_LOOSE = (
    "Step ",
    "--->",
    "Sending build context to Docker daemon",
    "Running in ",
    "Removed intermediate container ",
    "Successfully built ",
    "Successfully tagged ",
)

_SUPPRESSED_CONTAINS = (
    "Handles  NPM(K)",
    "ProcessName",
)


def should_suppress(line: str) -> bool:
    s = str(line)
    stripped = s.lstrip()
    return stripped.startswith(_SUPPRESSED_PREFIXES_LOOSE) or s.startswith(_SUPPRESSED_PREFIXES) or any(x in s for x in _SUPPRESSED_CONTAINS)


def sanitize_line(line: str) -> str:
    s = str(line)
    s = re.sub(r"\boutput_dir\s*=\s*[^\s\)]+", "output_dir=<redacted>", s, flags=re.IGNORECASE)
    s = re.sub(r"\bbase_dir\s*=\s*[^\s\)]+", "base_dir=<redacted>", s, flags=re.IGNORECASE)
    s = re.sub(r"\b[A-Za-z]:\\[^\s\"\']+", "<redacted_path>", s)
    return s


def sanitize_multiline(raw: str) -> str:
    if not raw:
        return ""

    out_lines: list[str] = []
    for line in str(raw).splitlines():
        if should_suppress(line):
            continue
        out_lines.append(sanitize_line(line))
    return "\n".join(out_lines)

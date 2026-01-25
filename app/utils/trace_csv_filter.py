from __future__ import annotations


def filter_trace_csv_lines(csv_file_path: str, target_exe: str | None):
    target_exe_lower = (target_exe or "").lower()
    if not target_exe_lower:
        return None

    target_exe_lower_no_ext = target_exe_lower[:-4] if target_exe_lower.endswith(".exe") else target_exe_lower

    filtered_lines: list[str] = []
    with open(csv_file_path, "r", encoding="utf-8", errors="ignore") as f:
        header = f.readline()
        if header:
            filtered_lines.append(header)

        found = False
        for line in f:
            if not found:
                l = line.lower()
                if (
                    ("," + target_exe_lower + ",") in l
                    or ("\\" + target_exe_lower) in l
                    or ("\\" + target_exe_lower_no_ext + ".exe") in l
                    or (" " + target_exe_lower) in l
                    or (" " + target_exe_lower_no_ext) in l
                ):
                    found = True

            if found:
                filtered_lines.append(line)

    if len(filtered_lines) <= 1:
        return None

    return filtered_lines

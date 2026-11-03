#!/usr/bin/env python3
"""Digital Forensic Investigation Toolkit - educational file triage utility."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta",
    ".scr", ".jar", ".zip", ".rar", ".7z"
}
SUSPICIOUS_NAME_PATTERNS = [
    r"^\.?hidden", r"password", r"credential", r"dump", r"payload",
    r"keylog", r"ransom", r"invoice.*\.(exe|js|vbs)$"
]
CHUNK_SIZE = 1024 * 1024

FILE_SIGNATURES = [
    (b"%PDF-", "PDF document", {".pdf"}),
    (b"\x89PNG\r\n\x1a\n", "PNG image", {".png"}),
    (b"\xff\xd8\xff", "JPEG image", {".jpg", ".jpeg"}),
    (b"GIF87a", "GIF image", {".gif"}),
    (b"GIF89a", "GIF image", {".gif"}),
    (b"PK\x03\x04", "ZIP archive", {".zip", ".docx", ".xlsx", ".pptx"}),
    (b"Rar!\x1a\x07", "RAR archive", {".rar"}),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", {".7z"}),
    (b"\x1f\x8b", "GZIP archive", {".gz"}),
    (b"SQLite format 3\x00", "SQLite database", {".db", ".sqlite", ".sqlite3"}),
    (b"MZ", "Windows PE/DOS executable", {".exe", ".dll", ".scr"}),
    (b"\x7fELF", "ELF executable", {".elf", ".so"}),
]


def identify_file_signature(path: Path) -> tuple[str, str]:
    """Identify common file formats from header bytes without executing files."""
    try:
        with path.open("rb") as handle:
            header = handle.read(32)
    except OSError:
        return "Unreadable", "Could not read file header"
    if not header:
        return "Empty file", "No content to identify"
    for magic, description, extensions in FILE_SIGNATURES:
        if header.startswith(magic):
            if path.suffix.lower() in extensions:
                return description, "Extension matches common type"
            return description, f"Extension mismatch or uncommon: {path.suffix.lower() or '[none]'}"
    try:
        header.decode("utf-8")
        return "Text/UTF-8 or unknown", "No known binary signature"
    except UnicodeDecodeError:
        return "Unknown binary format", "No known signature; manual review may be needed"


def find_duplicate_groups(inventory: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_hash: dict[str, list[str]] = {}
    for item in inventory:
        by_hash.setdefault(item["sha256"], []).append(item["relative_path"])
    return [{"sha256": digest, "files": paths, "count": len(paths)}
            for digest, paths in by_hash.items() if len(paths) > 1]


def iso_timestamp(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(timespec="seconds")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def triage_flags(path: Path) -> list[str]:
    flags = []
    suffix = path.suffix.lower()
    if suffix in SUSPICIOUS_EXTENSIONS:
        flags.append(f"Review file type: {suffix}")
    name = path.name.lower()
    for pattern in SUSPICIOUS_NAME_PATTERNS:
        if re.search(pattern, name, flags=re.IGNORECASE):
            flags.append(f"Review filename pattern: {pattern}")
    if path.name.startswith("."):
        flags.append("Hidden-style filename")
    return sorted(set(flags))


def inventory_file(path: Path, root: Path) -> dict[str, Any]:
    stat = path.stat()
    relative = path.relative_to(root).as_posix()
    detected_type, extension_check = identify_file_signature(path)
    flags = triage_flags(path)
    if extension_check.startswith("Extension mismatch"):
        flags.append("Check file extension against detected signature")
    return {
        "relative_path": relative,
        "file_name": path.name,
        "extension": path.suffix.lower(),
        "detected_file_type": detected_type,
        "extension_check": extension_check,
        "size_bytes": stat.st_size,
        "created_utc": iso_timestamp(stat.st_ctime),
        "modified_utc": iso_timestamp(stat.st_mtime),
        "accessed_utc": iso_timestamp(stat.st_atime),
        "sha256": sha256_file(path),
        "triage_flags": sorted(set(flags)),
        "analysis_status": "hashed"
    }


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            normalized = dict(row)
            if isinstance(normalized.get("triage_flags"), list):
                normalized["triage_flags"] = "; ".join(normalized["triage_flags"])
            writer.writerow({key: normalized.get(key, "") for key in fields})


def analyze(source: Path, case_id: str, examiner: str, notes: str, output: Path) -> Path:
    source = source.expanduser().resolve()
    output = output.expanduser().resolve()
    if not source.exists() or not source.is_dir():
        raise ValueError(f"Evidence source folder does not exist or is not a directory: {source}")
    if source == output or source in output.parents:
        # Output inside source would cause the tool to ingest its own report on later runs.
        if output == source or source in output.parents:
            raise ValueError("Output folder must be outside the evidence source folder.")

    files = sorted(p for p in source.rglob("*") if p.is_file())
    inventory = []
    errors = []
    for path in files:
        try:
            inventory.append(inventory_file(path, source))
        except (OSError, PermissionError) as exc:
            errors.append({"path": str(path.relative_to(source)), "error": str(exc)})

    timeline = []
    for item in inventory:
        for field, event_type in (
            ("created_utc", "filesystem_created"),
            ("modified_utc", "filesystem_modified"),
            ("accessed_utc", "filesystem_accessed"),
        ):
            timeline.append({
                "timestamp_utc": item[field],
                "event_type": event_type,
                "relative_path": item["relative_path"],
                "sha256": item["sha256"]
            })
    timeline.sort(key=lambda x: (x["timestamp_utc"], x["relative_path"], x["event_type"]))

    flagged = [item for item in inventory if item["triage_flags"]]
    duplicate_groups = find_duplicate_groups(inventory)
    total_bytes = sum(item["size_bytes"] for item in inventory)
    now = datetime.now(timezone.utc)
    safe_case = re.sub(r"[^A-Za-z0-9_.-]+", "_", case_id).strip("._") or "CASE"
    case_dir = output / f"{safe_case}_{now.strftime('%Y%m%d_%H%M%S')}"
    case_dir.mkdir(parents=True, exist_ok=False)

    inventory_fields = [
        "relative_path", "file_name", "extension", "detected_file_type", "extension_check",
        "size_bytes", "created_utc", "modified_utc", "accessed_utc", "sha256",
        "triage_flags", "analysis_status"
    ]
    timeline_fields = ["timestamp_utc", "event_type", "relative_path", "sha256"]
    write_csv(case_dir / "evidence_inventory.csv", inventory, inventory_fields)
    write_csv(case_dir / "timeline.csv", timeline, timeline_fields)

    report = {
        "case": {
            "case_id": case_id,
            "examiner": examiner,
            "notes": notes,
            "analysis_started_utc": now.isoformat(timespec="seconds"),
            "source_folder": str(source),
            "tool": "Digital Forensic Investigation Toolkit",
            "tool_version": "2.0.0"
        },
        "summary": {
            "files_discovered": len(files),
            "files_hashed": len(inventory),
            "files_with_triage_flags": len(flagged),
            "duplicate_hash_groups": len(duplicate_groups),
            "total_size_bytes": total_bytes,
            "processing_errors": len(errors)
        },
        "flagged_files": flagged,
        "duplicate_groups": duplicate_groups,
        "processing_errors": errors,
        "inventory": inventory,
        "limitations": [
            "This is preliminary file triage, not a validated forensic acquisition tool.",
            "Filesystem timestamps are leads and can be changed or affected by copying.",
            "A triage flag is not proof of malicious activity.",
            "File signature identification covers common formats only.",
            "Deleted files, disk unallocated space, registry hives, event logs and memory are not parsed."
        ]
    }
    (case_dir / "case_report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    lines = [
        "DIGITAL FORENSIC INVESTIGATION TOOLKIT",
        "=" * 44,
        f"Case ID: {case_id}",
        f"Examiner: {examiner}",
        f"Analysis started (UTC): {now.isoformat(timespec='seconds')}",
        f"Source folder: {source}",
        f"Notes: {notes or 'None'}",
        "",
        "SUMMARY",
        f"Files discovered: {len(files)}",
        f"Files successfully hashed: {len(inventory)}",
        f"Files with triage flags: {len(flagged)}",
        f"Duplicate SHA-256 groups: {len(duplicate_groups)}",
        f"Total size (bytes): {total_bytes}",
        f"Processing errors: {len(errors)}",
        "",
        "FILES REQUIRING REVIEW"
    ]
    if flagged:
        for item in flagged:
            lines.append(f"- {item['relative_path']} | {', '.join(item['triage_flags'])}")
    else:
        lines.append("- No configured triage flags were triggered.")
    lines += ["", "DUPLICATE FILE GROUPS"]
    if duplicate_groups:
        for group in duplicate_groups:
            lines.append(f"- SHA256 {group['sha256']}: {', '.join(group['files'])}")
    else:
        lines.append("- No duplicate file hashes found.")
    lines += [
        "",
        "INTERPRETATION",
        "Flags identify items for manual review; they do not establish maliciousness.",
        "Filesystem timestamps are not definitive proof of when an action occurred.",
        "",
        "LIMITATIONS",
        "- Preliminary file triage only; not a forensic acquisition tool.",
        "- Does not parse deleted data, registry, event logs, browser artifacts or RAM.",
        "- Use validated tools and documented procedures for real investigations."
    ]
    (case_dir / "case_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return case_dir


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inventory and hash a copied evidence folder; generate DFIR reports."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    cmd = sub.add_parser("analyze", help="Analyze a working-copy evidence folder")
    cmd.add_argument("--source", required=True, help="Path to evidence working-copy folder")
    cmd.add_argument("--case-id", required=True, help="Investigation case identifier")
    cmd.add_argument("--examiner", default="Not specified", help="Examiner name")
    cmd.add_argument("--notes", default="", help="Short case notes")
    cmd.add_argument("--output", default="reports", help="Output directory (outside source)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = analyze(
            Path(args.source), args.case_id, args.examiner, args.notes, Path(args.output)
        )
        print(f"[+] Analysis complete. Reports saved to: {result}")
        print("[!] Review all flagged files manually. A flag is not proof of maliciousness.")
        return 0
    except (ValueError, OSError) as exc:
        print(f"[!] Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

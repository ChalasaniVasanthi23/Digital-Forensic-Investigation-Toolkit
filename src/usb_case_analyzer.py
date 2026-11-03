
import csv
from pathlib import Path
from collections import Counter
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = BASE_DIR / "sample_evidence_case2"
REPORT_DIR = BASE_DIR / "reports" / "CASE-002"
OUTPUT_FILE = REPORT_DIR / "usb_investigation_report.txt"

def read_csv(filename):
    path = EVIDENCE_DIR / filename
    with path.open("r", newline="", encoding="utf-8-sig") as file:
        return list(csv.DictReader(file))

def main():
    connections = read_csv("usb_connection_history.csv")
    copied_files = read_csv("copied_files.csv")

    connections.sort(
        key=lambda row: datetime.strptime(
            row["timestamp"], "%Y-%m-%d %H:%M:%S"
        )
    )

    copied_files.sort(
        key=lambda row: datetime.strptime(
            row["timestamp"], "%Y-%m-%d %H:%M:%S"
        )
    )

    devices = sorted({
        row["device_name"] for row in connections
    })
    users = sorted({
        row["user"] for row in connections
    })
    event_counts = Counter(
        row["event"] for row in connections
    )

    total_bytes = sum(
        int(row["size_bytes"]) for row in copied_files
    )

    lines = [
        "USB DATA THEFT INVESTIGATION REPORT",
        "=" * 40,
        "Case ID: CASE-002",
        "Examiner: Not specified",
        "Evidence type: SIMULATED TRAINING DATA",
        "",
        "1. USB CONNECTION TIMELINE",
        "-" * 30,
    ]

    for row in connections:
        lines.append(
            f'{row["timestamp"]} | {row["device_name"]} | '
            f'{row["event"]} | User: {row["user"]}'
        )

    lines += [
        "",
        "2. FILE COPY RECORDS",
        "-" * 30,
    ]

    for row in copied_files:
        lines.append(
            f'{row["timestamp"]} | {row["file_name"]} | '
            f'{row["size_bytes"]} bytes | '
            f'Destination: {row["destination_device"]}'
        )

    lines += [
        "",
        "3. INVESTIGATION SUMMARY",
        "-" * 30,
        f"USB devices recorded: {len(devices)}",
        f"Users recorded: {', '.join(users)}",
        f"Connection events: {len(connections)}",
        f"File-copy records: {len(copied_files)}",
        f"Total recorded file size: {total_bytes} bytes",
        "",
        "Event counts:",
    ]

    for event, count in sorted(event_counts.items()):
        lines.append(f"  {event}: {count}")

    lines += [
        "",
        "4. FINDINGS AND LIMITATIONS",
        "-" * 30,
        "The simulated records show a USB connection, mount,",
        "file-copy activity and disconnection.",
        "Three simulated file-copy records are present.",
        "These records alone do not prove unauthorized theft.",
        "No actual USB device or Windows event logs were examined.",
        "All evidence is simulated for educational purposes.",
    ]

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text("\n".join(lines), encoding="utf-8")

    print("[+] USB investigation analysis completed.")
    print(f"[+] Report saved to: {OUTPUT_FILE}")
    print(f"[+] File-copy records: {len(copied_files)}")
    print(f"[+] Total bytes: {total_bytes}")

if __name__ == "__main__":
    main()

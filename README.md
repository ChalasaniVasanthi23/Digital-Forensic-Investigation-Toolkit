# Digital Forensic Investigation Toolkit (DFIT)

A Python-based educational toolkit for preliminary digital-forensics triage of **working copies** of evidence files. It inventories files, calculates SHA-256 hashes, identifies selected file signatures, flags items for review, groups duplicate files, and creates investigation reports.

> **Important:** This is an educational triage tool, not a validated forensic acquisition platform. It does not create forensic disk images, guarantee chain of custody, or prove that suspicious activity was malicious. The USB investigation uses simulated training CSV data. Never run investigations on systems or data without authorization.

## Features

- Recursive evidence-folder inventory
- SHA-256 hashing for file-integrity comparison
- File size, extension, and filesystem timestamps
- Basic filename/extension-based triage flags
- File-signature identification and extension-mismatch warnings
- Duplicate-file grouping using SHA-256
- CSV evidence inventory and JSON/text case reports
- Timestamp-sorted file activity timeline
- Simulated USB connection and file-copy activity analysis
- Unit tests using Python's built-in `unittest` framework

## Requirements

- Python 3.9 or later
- Windows, macOS, or Linux
- No third-party Python packages required

Check your Python installation:

```bash
python --version
```

On some systems, use `python3` instead of `python`.

## Project structure

```text
Digital_Forensic_Investigation_Toolkit/
├── src/
│   ├── dfit.py
│   └── usb_case_analyzer.py
├── sample_evidence/
│   ├── hidden_review.txt
│   ├── meeting_notes.txt
│   ├── readme_evidence.txt
│   └── sample_script.ps1
├── sample_evidence_case2/
│   ├── case_notes.txt
│   ├── copied_files.csv
│   └── usb_connection_history.csv
├── tests/
│   └── test_dfit.py
├── reports/                 # Generated reports are not committed
├── screenshots/             # Add your own application screenshots here
├── .gitignore
├── LICENSE
└── README.md
```

## Quick start

Open a terminal in the project root (the folder containing `README.md`).

### Case 1 — Digital forensic file triage

Run the analyzer against the included sample evidence:

```bash
python src/dfit.py analyze --source sample_evidence --case-id CASE-001 --examiner "Investigator"
```

The tool creates a timestamped report directory under `reports/` containing:

- `evidence_inventory.csv` — file metadata and SHA-256 hashes
- `timeline.csv` — file activity timeline based on available filesystem timestamps
- `case_report.json` — structured case results
- `case_report.txt` — readable case summary

### Case 2 — Simulated USB activity investigation

First inventory and hash the second sample evidence folder:

```bash
python src/dfit.py analyze --source sample_evidence_case2 --case-id CASE-002 --examiner "Investigator"
```

Then analyze the simulated USB event and copy records:

```bash
python src/usb_case_analyzer.py
```

The USB analyzer writes its summary to:

```text
reports/CASE-002/usb_investigation_report.txt
```

The report summarizes connection events, users, file-copy records, and recorded byte totals. These are simulated records and must not be treated as proof of actual data theft.

## Run the tests

From the project root:

```bash
python -m unittest discover -s tests -v
```

The tests cover SHA-256 calculation, triage flags, report generation, PDF signature identification, and duplicate-hash grouping.

## Screenshots

After running the project, add genuine screenshots to the `screenshots/` folder. Suggested screenshots:

1. Terminal showing Case 1 analysis completed.
2. Generated evidence inventory CSV opened in a spreadsheet or text editor.
3. Case report showing the SHA-256 and triage results.
4. Terminal showing Case 2 USB analysis completed.
5. USB investigation report output.
6. Unit-test output showing the test results.

Do not add screenshots containing private files, personal paths, usernames, or sensitive evidence.

## Limitations

- Analyze a read-only or working copy of evidence; this tool does not acquire or preserve original media.
- Filesystem timestamps can change when files are copied and are not, by themselves, reliable proof of an event.
- Triage flags are heuristic indicators for human review, not malware verdicts.
- File-signature checks cover only the signatures implemented in the source code.
- The USB case is based on supplied simulated CSV records, not live Windows event logs or a physical USB device.

## License

This project is provided under the MIT License. See [LICENSE](LICENSE).

# Digital Forensic Investigation Toolkit (DFIT)

A Python-based Digital Forensic Investigation Toolkit designed for preliminary digital-forensics triage and evidence analysis.

DFIT helps investigators analyze working copies of evidence files by generating SHA-256 hashes, identifying file signatures, detecting suspicious file indicators, grouping duplicate files, creating evidence timelines, and generating investigation reports.

> **Disclaimer:** This is an educational digital-forensics triage tool, not a certified forensic acquisition platform. It does not create forensic disk images, guarantee chain of custody, or prove malicious activity. USB investigation is performed using simulated training data. Always obtain authorization before analyzing any system or data.

## Features

- Recursive evidence file inventory
- SHA-256 file hashing for integrity comparison
- File size, extension, and filesystem timestamp collection
- Suspicious filename and extension detection
- File signature identification
- File extension mismatch warnings
- Duplicate file detection using SHA-256 hashes
- Evidence inventory generation in CSV format
- Investigation reports in JSON and TXT formats
- Timestamp-based evidence timeline generation
- Simulated USB connection activity analysis
- Simulated USB file-copy investigation
- Automated unit testing using Python unittest

## Technologies Used

- Python 3
- SHA-256 Hashing
- CSV and JSON
- File System Analysis
- Digital Forensics
- Python unittest

## Requirements

- Python 3.9 or later
- Windows, Linux, or macOS
- No third-party Python packages required

Check Python installation:

```bash
python --version
```

## Project Structure

```text
Digital-Forensic-Investigation-Toolkit/
│
├── src/
│   ├── dfit.py
│   └── usb_case_analyzer.py
│
├── tests/
│   └── test_dfit.py
│
├── sample_evidence/
│   ├── hidden_review.txt
│   ├── meeting_notes.txt
│   ├── readme_evidence.txt
│   └── sample_script.ps1
│
├── sample_evidence_case2/
│   ├── case_notes.txt
│   ├── copied_files.csv
│   └── usb_connection_history.csv
│
├── screenshots/
│   ├── 01_project_execution.png
│   ├── 02_sha256_hashing.png
│   ├── 03_evidence_analysis.png
│   ├── 04_suspicious_file_detection.png
│   ├── 05_evidence_timeline.png
│   ├── 06_usb_investigation_execution.png
│   ├── 07_usb_investigation_report.png
│   ├── 08_unit_testing.png
│   └── 09_generated_reports.png
│
├── reports/
│   └── .gitkeep
│
├── .gitignore
├── LICENSE
└── README.md
```

## Installation and Execution

### 1. Clone the Repository

```bash
git clone https://github.com/ChalasaniVasanthi23/Digital-Forensic-Investigation-Toolkit.git
```

Open the project directory:

```bash
cd Digital-Forensic-Investigation-Toolkit
```

### 2. Case 1 – Digital Forensic File Analysis

Run the forensic analyzer using the sample evidence folder:

```bash
python src/dfit.py analyze --source sample_evidence --case-id CASE-001 --examiner "Investigator"
```

The tool analyzes the evidence files and generates investigation reports inside the `reports/` directory.

Generated files include:

- `evidence_inventory.csv` – Evidence file details and SHA-256 hashes.
- `timeline.csv` – File activity timeline based on available filesystem timestamps.
- `case_report.json` – Structured investigation results.
- `case_report.txt` – Readable investigation summary.

### 3. Case 2 – USB Activity Investigation

First, analyze the second sample evidence folder:

```bash
python src/dfit.py analyze --source sample_evidence_case2 --case-id CASE-002 --examiner "Investigator"
```

Then execute the USB investigation analyzer:

```bash
python src/usb_case_analyzer.py
```

The USB analyzer processes simulated USB connection and file-copy activity records.

Expected report location:

```text
reports/CASE-002/usb_investigation_report.txt
```

The report summarizes recorded USB connections, users, file-copy activities, and recorded data-transfer totals.

**Note:** The USB investigation uses simulated CSV records. It does not monitor physical USB devices or establish actual data theft.

## Run Unit Tests

Execute the following command from the project root:

```bash
python -m unittest discover -s tests -v
```

The unit tests cover implemented functionality such as:

- SHA-256 hash calculation
- Suspicious file triage flags
- Report generation
- File signature identification
- Duplicate hash grouping

## Screenshots

The following screenshots demonstrate the project execution and investigation results.

| No. | Screenshot | Description |
|---|---|---|
| 01 | Project Execution | Forensic analysis execution |
| 02 | SHA-256 Hashing | Evidence file hash results |
| 03 | Evidence Analysis | Investigation report |
| 04 | Suspicious File Detection | File triage indicators |
| 05 | Evidence Timeline | Evidence activity timeline |
| 06 | USB Investigation Execution | USB analyzer execution |
| 07 | USB Investigation Report | USB investigation results |
| 08 | Unit Testing | Automated test results |
| 09 | Generated Reports | Generated investigation reports |

All screenshots are stored in the `screenshots/` directory.

## Limitations

- The toolkit is intended for educational and preliminary forensic triage purposes.
- It analyzes working copies of evidence and does not acquire forensic disk images.
- Filesystem timestamps may change when files are copied or modified.
- Suspicious file indicators are heuristic warnings and do not prove malware infection.
- File signature identification is limited to the signatures implemented in the source code.
- Duplicate detection is based on SHA-256 hash comparison.
- USB investigation uses simulated training CSV data rather than live device monitoring.
- Investigation results require manual verification by an authorized investigator.

## Future Enhancements

- Integration with live Windows event logs.
- Advanced file metadata analysis.
- Additional file signature support.
- Interactive graphical investigation dashboard.
- Advanced forensic timeline visualization.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Author

**Digital Forensic Investigation Toolkit (DFIT)**

Developed as an educational cybersecurity and digital-forensics project.

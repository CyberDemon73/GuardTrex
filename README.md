---

# GuardTrex

GuardTrex is a comprehensive security scanning tool designed to identify and report potential vulnerabilities, sensitive data leaks, and insecure practices within a codebase. It uses regular expressions to scan for common security issues such as hardcoded secrets, API keys, and database credentials. GuardTrex also supports taint tracking for sensitive data, helping you ensure secure data handling throughout your project.

## Features

- **Sensitive Data Detection**: Finds hardcoded credentials, API keys, and other sensitive information.
- **Taint Tracking**: Monitors sensitive variable usage to ensure they’re not exposed in logs or external requests.
- **File Hashing for Incremental Scans**: Only scans files that have changed, speeding up the process on large projects.
- **Multi-File Support**: Scans files with extensions `.java`, `.properties`, `.xml`, `.py`, `.js`, `.yml`, and `.json`.
- **Severity-Based Reporting**: Classifies findings by severity (High, Medium, Low, Informational) with suggested mitigations.
- **Export Options**: Outputs results to CSV or HTML formats for easy reporting.

## Installation

1. Clone this repository:
   ```bash
   git clone [<repo-url>](https://github.com/CyberDemon73/GuardTrex.git)
   cd GuardTrex
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the tool with the following command:
```bash
python guardtrex.py <directory> [--format csv|html]
```

### Arguments

- `<directory>`: Path to the directory to scan.
- `--format`: Format of the output report. Options are `csv` (default) or `html`.

### Example

```bash
python guardtrex.py ./project_directory --format csv
```

## Output

GuardTrex generates a report containing:

- **File**: The file where the vulnerability is found.
- **Line**: Line number of the issue.
- **Description**: Description of the security issue.
- **Severity**: Severity classification (High, Medium, Low, Informational).
- **Fix Suggestion**: Recommended actions to resolve the issue.
- **Code Snippet**: Code snippet providing context around the finding.

The report is saved as `security_scan_report.csv` or in HTML format if specified.

## Logging

All scanning activities and any errors encountered are logged in `security_scan.log`.

## Example Issues Detected

1. **API Keys and Secrets**: Detects hardcoded secrets and platform tokens.
2. **Passwords and Authentication Data**: Flags hardcoded passwords and session tokens.
3. **Database Connection Strings**: Identifies JDBC and SQL connection strings in the code.
4. **Cryptographic Keys**: Alerts for hardcoded cryptographic keys.
5. **Personally Identifiable Information (PII)**: Finds patterns related to SSNs, DOBs, and phone numbers.
6. **Credit Card Numbers**: Identifies major credit card number patterns.
7. **Insecure Protocols**: Flags URLs using insecure HTTP protocols.
8. **Debugging Information**: Detects debugging flags and localhost URLs.
9. **IP Address Exposure**: Warns about exposed IP addresses in code.

## Contribution

Contributions are welcome! To add new patterns or improve functionality, submit a pull request.

## License

This project is licensed under the MIT License.

---

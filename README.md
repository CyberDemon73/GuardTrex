# GuardTrex

**GuardTrex** is an advanced source code security scanner designed to identify vulnerabilities, sensitive data leaks, and insecure practices within your codebase. This tool employs custom regex-based scanning to detect common security issues across multiple file types, providing a streamlined approach to secure code management.

## Key Features

- **Comprehensive Vulnerability Detection**: Detects hardcoded credentials, API keys, insecure endpoints, and other critical security misconfigurations.
- **Taint Tracking for Sensitive Data**: Monitors the flow of sensitive variables, ensuring they aren’t exposed in logs or external requests.
- **Incremental Scanning with File Hashing**: Efficiently scans only modified files, accelerating analysis for large projects.
- **Multi-File Type Compatibility**: Supports various file extensions, including `.java`, `.properties`, `.xml`, `.py`, `.js`, `.yml`, and `.json`.
- **Severity-Based Classification**: Categorizes findings into severity levels (Critical, High, Medium, Low), with actionable mitigation steps.
- **Flexible Report Export**: Outputs findings in CSV and/or HTML formats for streamlined documentation and reporting.
- **Workspace Management**: Organize scan outputs, logs, and reports within a dedicated workspace folder for each run, ensuring efficient result tracking.

## Recent Enhancements

### Workspace Management

The **Workspace** feature adds a `--workspace` parameter, allowing you to organize scan outputs under a specified workspace name within the `Workspaces/` directory. This keeps logs, caches, and reports structured by project or scan run for better traceability.

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/CyberDemon73/GuardTrex.git
   cd GuardTrex
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run GuardTrex with the following syntax:

```bash
python guardtrex.py <directory> --workspace <workspace_name> [--format csv|html|both]
```

### Arguments

- `<directory>`: Directory to scan.
- `--workspace <workspace_name>`: Creates a workspace folder under `Workspaces/` to store all logs, caches, and reports.
- `--format <csv|html|both>`: Format of the report output. Options include `csv`, `html`, or both.
- `--interactive`: Runs in guided mode for user-friendly setup.

### Example Command

This command will scan the `src` directory and save the output files in `Workspaces/ProjectX/`.
```bash
python3 guardtrex.py ./src --workspace ProjectX --format both
```

The following command will give you an interactive window directly as shown below
```bash
python3 guardtrex.py --interactive --workspace ProjectX
```

## Outputs

GuardTrex produces a structured report with the following details:

- **File**: Location of the detected issue.
- **Line**: Line number of the detected issue.
- **Description**: Explanation of the detected vulnerability.
- **Severity**: Classification of the issue (Critical, High, Medium, Low).
- **Fix Suggestion**: Recommended remediation steps.
- **Code Snippet**: Contextual code excerpt around the finding.

Reports are saved as `security_scan_report.csv` and/or `security_scan_report.html` in the specified workspace.

### Logging

GuardTrex records all activities and errors in `<workspace>/security_scan.log` for comprehensive auditing and troubleshooting.

## Example Issues Detected

**1. Configuration & Security Settings**
   - Exposed Actuator Endpoints
   - Disabled CSRF Protection
   - Missing Content Security Policy (CSP)

**2. Hardcoded Secrets & Sensitive Data**
   - Hardcoded API keys, secrets, and tokens
   - Insecure password storage configurations

**3. Insecure Transmission and Endpoint Security**
   - Unencrypted database connection strings
   - Hardcoded cryptographic keys

**4. Personally Identifiable Information (PII)**
   - Social Security Numbers
   - Contact and payment information

**5. Logging and External Data Exposure**
   - Sensitive data logged in plain text
   - Data transmitted to external requests

**6. Injection Vulnerabilities**
   - Command injection
   - SQL injection

**7. Outdated Libraries and Frameworks**
   - Deprecated OpenSSL versions
   - Known vulnerable dependency versions

## Visual Documentation

### Demo

<img src="https://raw.githubusercontent.com/CyberDemon73/GuardTrex/main/Images/Demo.png" alt="Demo-Image" width="1000">

### Report Samples

<img src="https://raw.githubusercontent.com/CyberDemon73/GuardTrex/main/Images/Report-Sample-1.png" alt="Report-Sample" width="1000">
<img src="https://raw.githubusercontent.com/CyberDemon73/GuardTrex/main/Images/Report-Sample.png" alt="Report-Sample" width="1000">

### Diagram

<img src="https://raw.githubusercontent.com/CyberDemon73/GuardTrex/main/Images/Diagram.svg" alt="Diagram" width="1000">

## Contribution

Contributions are welcome. To add new patterns or improve functionality, submit a pull request.

## License

This project is licensed under the MIT License.

--- 

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
   git clone (https://github.com/CyberDemon73/GuardTrex.git)
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

**1. Configuration and Security Settings**
   - **Exposure of Sensitive Endpoints**
     - `management.endpoints.web.exposure.include=*` - All Actuator Endpoints Exposed (High)
     - `management.endpoints.web.exposure.include=health|info` - Exposed Actuator Endpoint (Medium)
     - `spring.h2.console.enabled=true` - Insecure H2 Console Exposure (High)
     - `spring.boot.admin.client.enabled=true` - Debugging Enabled in Production (High)
   - **Cross-Site Request Forgery (CSRF)**
     - `spring.security.csrf.enabled=false` - CSRF Protection Disabled (High)
   - **Content Security Policy (CSP)**
     - `Content-Security-Policy: default-src *;` - Weak/Missing CSP (Medium)
   - **Transport Layer Security (TLS)**
     - `server.ssl.enabled=false` - SSL/TLS Disabled (High)
     - `http.server.secure-port=8080` - HTTP Connection Allowed (High)
   - **Cross-Origin Resource Sharing (CORS)**
     - `spring.web.cors.allowed-origin-patterns=*` - CORS Policy Allows All Origins (High)
   - **Clickjacking Protection**
     - `X-Frame-Options: ALLOW` - X-Frame-Options Header Allows Embedding (Medium)
     
**2. Hardcoded Secrets and Sensitive Data**
   - **API Keys and Secrets**
     - `api_key|secret|token` - Hardcoded API Key or Secret (High)
     - `aws_secret|aws_access_key|s3_bucket` - AWS Secret Key or S3 Bucket Exposure (High)
     - `github|gitlab|bitbucket|slack` - Hardcoded GitHub/GitLab/Slack Token (High)
     - `firebase_api_key` - Firebase API Key Exposure (High)
     - `gcp_secret|google_cloud` - Google Cloud Secret or API Key Exposure (High)
     - `azure_secret|azure_key` - Azure Secret Key Exposure (High)
   - **Password Storage**
     - `spring.data.source.password` - Insecure Password Storage (High)
     - `password|passwd|pwd|auth` - Hardcoded Password (High)
   - **Tokens and Session Management**
     - `auth|oauth|session|jwt` - Sensitive Token Declaration (High)
     - `session_id|sess_id` - Hardcoded Session ID or Token (High)
     - `oauth|bearer|access|refresh` - Hardcoded OAuth/Bearer/Access/Refresh Token (High)

**3. Insecure Data Transmission and Endpoint Security**
   - **Database Connection Strings**
     - `jdbc:*://` - JDBC Connection String (High)
     - `mongodb|mysql|oracle|postgres|mssql` - SQL Connection String (High)
     - `redis|memcached` - Insecure Cache Connection String (Medium)
   - **Cryptographic Keys**
     - `private_key|public_key|pem|rsa_key` - Hardcoded Cryptographic Key (High)
     - `BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY` - Hardcoded Private Key (High)
     - `ssh-rsa|ssh-ed25519` - Potential SSH Public Key (Medium)
     - `aes_key|des_key|3des_key|blowfish_key` - Hardcoded Symmetric Encryption Key (High)
   - **Insecure Protocols**
     - `http://` - Insecure HTTP URL (Medium)
     - `ftp|smb://` - FTP/SMB URL (Medium)

**4. Personally Identifiable Information (PII)**
   - **Social Security and ID Numbers**
     - `\d{3}-\d{2}-\d{4}` - Potential SSN (High)
     - `\d{4}-\d{6}-\d{4}` - National ID or Tax ID Number (High)
   - **Personal Information**
     - `dob|date_of_birth` - Hardcoded Date of Birth (High)
     - `phone_number|contact` - Hardcoded Phone Number (Medium)
   - **Credit Card Information**
     - `Visa`, `MasterCard`, `American Express`, `Discover` patterns - Potential Credit Card Numbers (High)

**5. Sensitive Data in Logs and External Requests**
   - **Logging Sensitive Data**
     - `print|console.log|logger.info|logger.debug|logging.info` - Sensitive Data in Logs (High)
   - **External Data Transmission**
     - `fetch|requests.get|requests.post|http.get|http.post` - Sensitive Data in External Requests (High)

**6. Deprecated Libraries and Insecure Framework Versions**
   - **Outdated Libraries**
     - `openssl=1.0.x` - Deprecated OpenSSL Version (High)

**7. Injection Vulnerabilities**
   - **Command Injection**
     - `eval|exec|subprocess.call|os.system|ProcessBuilder` - Potential Command Injection (High)
   - **SQL Injection**
     - `PreparedStatement(...);` - SQL Injection via Dynamic Query (High)

**8. Framework-Specific Issues**
   - **Spring Boot Management Endpoints**
     - `spring.boot.admin|actuator|health|env|configprops|mappings|trace|loggers|heapdump|threaddump|metrics` - Potentially Exposed Spring Boot Actuator Endpoint (High)
   - **Hardcoded Spring Boot Database Credentials**
     - `spring.data.source.username|spring.data.source.password` - Hardcoded Database Credentials in Spring Boot (High)

**9. Control Flow and Access Control**
   - **Access Control and Authorization Checks**
     - `if(auth|login)` - Authentication/Authorization Check (Informational)
     - `if(isAdmin|role)` - Role-Based Access Control Check (Informational)

**10. Debugging and Development**
   - **Debugging Settings**
     - `debug|development=true|1` - Debug Mode Enabled (Medium)
   - **Non-Production URLs**
     - `dev|test|sandbox|staging url` - Development/Test URL (Low)

**11. IP Address and Whitelist Exposure**
   - **IP Addresses**
     - `(?:\d{1,3}\.){3}\d{1,3}` - IP Address Exposure (Medium)
   - **Hardcoded IP Whitelists**
     - `whitelist_ip` - Hardcoded IP Whitelist (Medium)

**12. Miscellaneous Sensitive Information**
   - **Application Secrets**
     - `app_secret|app_id|client_id|client_secret` - Hardcoded Application Secret (High)
   - **SMTP/Email/FTP/Proxy**
     - `smtp|mail|email|ftp|proxy` - SMTP/Email/FTP/Proxy URL Exposure (Medium)
   - **Authorization Headers**
     - `authorization_header|auth_header` - Hardcoded Authorization Header (High)
   - **Access and Refresh Tokens**
     - `access_token|refresh_token` - Hardcoded Access or Refresh Token (High)

## Illustrating Diagram

<img src="https://raw.githubusercontent.com/CyberDemon73/GuardTrex/main/Diagram.svg" alt="Diagram" width="1000">

## Contribution

Contributions are welcome! To add new patterns or improve functionality, submit a pull request.

## License

This project is licensed under the MIT License.

---

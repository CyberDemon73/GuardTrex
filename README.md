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

Here’s the updated **Example Issues Detected** section with the adjustments you've specified:

---

## Example Issues Detected

GuardTrex detects a variety of security issues that can arise in codebases, focusing on configuration errors, hardcoded secrets, sensitive data exposure, injection vulnerabilities, and more.

**1. Configuration & Security Settings**
   - **Insecure Actuator and Admin Endpoints**  
     - Exposes all actuator endpoints, risking sensitive system information.
   - **Disabled CSRF Protection**  
     - Disabling CSRF protection makes the application vulnerable to unauthorized actions.
   - **Missing Content Security Policy (CSP)**  
     - Lack of CSP allows content injection attacks, such as XSS.
   - **TLS/SSL Disabled**  
     - Disabling encryption exposes data in transit, making it susceptible to interception.
   - **Permissive CORS Policy**  
     - Allows access from all origins, risking data leakage across domains.
   - **Debugging Enabled in Production**  
     - Debug mode exposes detailed errors and internal information useful for attackers.

**2. Hardcoded Secrets & Sensitive Data**
   - **API Keys and Secrets**  
     - Hardcoded API keys expose applications to unauthorized access.
   - **Database Passwords**  
     - Storing plaintext passwords in source code poses a high risk of data exposure.
   - **Tokens and Session Management**  
     - Hardcoded session IDs or JWT secrets risk account hijacking and data compromise.

**3. Insecure Transmission & Endpoint Security**
   - **Database Connection Strings**  
     - Hardcoded database credentials can be exploited to access databases directly.
   - **Insecure HTTP Usage**  
     - Transmitting data over HTTP without encryption exposes it to interception.
   - **Unprotected Web Services**  
     - Exposes database consoles and other admin endpoints without protection.

**4. Personally Identifiable Information (PII)**
   - **Social Security & ID Numbers**  
     - Detects potential SSNs or similar formats that should not be hardcoded.
   - **Credit Card Numbers**  
     - Finds potential credit card numbers in code, which should be masked or securely stored.
   - **Sensitive Contact Details**  
     - Hardcoded phone numbers, emails, or addresses present a privacy risk.

**5. Sensitive Data in Logs & External Requests**
   - **Logging Sensitive Data**  
     - Logs containing sensitive data can expose this information if accessed.
   - **Unsecured External Transmission**  
     - Transmitting sensitive information over untrusted sources or protocols risks exposure.

**6. Injection Vulnerabilities**
   - **Command Injection**  
     - Command injection functions without sanitization can lead to arbitrary code execution.
   - **SQL Injection**  
     - Unparameterized database queries allow attackers to inject malicious SQL.
   - **XXE Vulnerability**  
     - XML external entities could be exploited to access local resources and sensitive data.

**7. Deprecated Libraries & Insecure Framework Versions**
   - **Outdated Dependency**  
     - Detects outdated versions of libraries like OpenSSL and Log4j, which may have known vulnerabilities.
   - **Insecure Framework Configuration**  
     - Allows the use of outdated protocols, increasing exposure to attacks.

**8. Control Flow & Access Control Issues**
   - **Improper Access Control Checks**  
     - Missing role-based access control checks can lead to privilege escalation.
   - **Publicly Exposed APIs**  
     - Exposes APIs without adequate access control, risking unauthorized data access.

**9. Debugging & Development Configurations**
   - **Exposed Debug Endpoints**  
     - Debug configurations should be disabled in production for security.
   - **Testing URLs in Production Code**  
     - Development or test environments should not be referenced in production.

**10. IP Address & Whitelist Exposure**
   - **Hardcoded IP Addresses**  
     - Exposes internal or sensitive IPs, potentially revealing infrastructure layout.
   - **Whitelisted IP Addresses**  
     - Hardcoding IP whitelists without dynamic configuration can compromise access control.

**11. Miscellaneous Sensitive Information**
   - **Application Secrets**  
     - Application secrets exposed in source code pose a security risk.
   - **SMTP/Email Credentials**  
     - Hardcoded email server credentials can lead to unauthorized email access.
   - **Authorization Headers**  
     - Hardcoded authorization tokens risk account compromise if leaked.

---

### Language-Specific Issues

GuardTrex also covers language-specific vulnerabilities that can arise from certain features and libraries used in different programming languages.

**Java**
   - **Insecure Deserialization**  
     - Identifies risky deserialization functions that could allow arbitrary code execution.
   - **Hardcoded Passwords in Java Properties Files**  
     - Detects sensitive credentials in `.properties` files commonly used in Java projects.
   - **Reflection and Dynamic Code Execution**  
     - Finds instances of dynamic code execution that may be exploitable if not secured.

**Python**
   - **Pickle Insecure Deserialization**  
     - Detects the use of `pickle` and other insecure serialization modules.
   - **Flask Debug Mode Enabled**  
     - Identifies instances of Flask applications running in debug mode, which should be disabled in production.
   - **Hardcoded API Keys in `.env` Files**  
     - Finds sensitive information in configuration files like `.env`.

**JavaScript/Node.js**
   - **Insecure `eval` Usage**  
     - Finds instances of `eval`, `Function` constructors, and similar patterns that allow arbitrary code execution.
   - **Hardcoded JWT Secrets**  
     - Detects hardcoded secrets used for JWT, which should be securely stored and dynamically configured.
   - **Improper CORS Configuration**  
     - Identifies overly permissive CORS settings, especially in Express.js applications.

**Ruby**
   - **Insecure YAML Deserialization**  
     - Detects YAML deserialization functions, which can be vulnerable to remote code execution if not properly handled.
   - **Rails `strong_parameters` Misconfiguration**  
     - Finds Rails applications with improperly configured strong parameters, potentially allowing mass assignment vulnerabilities.
   - **Secrets in Rails Configuration Files**  
     - Checks for sensitive keys in `secrets.yml` or `credentials.yml.enc`, which should be protected.

**PHP**
   - **Insecure SQL Queries**  
     - Finds SQL queries that concatenate user inputs, increasing SQL injection risks.
   - **Insecure File Uploads**  
     - Detects patterns for file uploads that lack proper validation, allowing malicious file types.
   - **Deprecated Function Usage**  
     - Identifies usage of deprecated or insecure PHP functions, such as `mysql_query` or `create_function`.

**.NET**
   - **Hardcoded Connection Strings**  
     - Detects connection strings hardcoded in `.config` files, which should be secured.
   - **Insecure ViewState**  
     - Checks for improperly configured `ViewState`, which can lead to tampering vulnerabilities.
   - **Weak Authentication Schemes**  
     - Identifies weak or outdated authentication schemes within ASP.NET applications.

--- 

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

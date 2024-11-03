import os
import re
import logging
import hashlib
import csv
import yaml
import xml.etree.ElementTree as ET
from colorama import Fore, Style, init
from lxml import etree
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor
import argparse
from datetime import datetime
from collections import defaultdict  # Import defaultdict here
from jinja2 import Template


# Initialize colorama
init(autoreset=True)

# Configure logging
logging.basicConfig(
    filename='security_scan.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

sensitive_data_map = {}  # Define this here as a global variable

# Define regex patterns with descriptions, severity, and automatic fix suggestions
PATTERNS = [

    (re.compile(r'management\.endpoints\.web\.exposure\.include\s*=\s*\*', re.IGNORECASE), 
     'All Actuator Endpoints Exposed', 'High', 'Limit exposure of Actuator endpoints to necessary endpoints only, and secure with authentication.'),
    (re.compile(r'management\.endpoints\.web\.exposure\.include\s*=\s*(health|info)', re.IGNORECASE), 
     'Exposed Actuator Endpoint (health/info)', 'Medium', 'Ensure that exposed endpoints are not disclosing sensitive information.'),

    # CSRF Protection Disabled
    (re.compile(r'spring\.security\.csrf\.enabled\s*=\s*false', re.IGNORECASE), 
     'CSRF Protection Disabled', 'High', 'Enable CSRF protection for all forms or secure endpoints requiring stateful interactions.'),

    # Insecure Password Storage (plaintext passwords)
    (re.compile(r'spring\.data\.source\.password\s*=\s*[\'"]?[a-zA-Z0-9]*[\'"]?', re.IGNORECASE), 
     'Insecure Password Storage', 'High', 'Store database credentials in a secure configuration provider or environment variable.'),
    
    # Weak or No Content Security Policy (CSP) Headers
    (re.compile(r'Content-Security-Policy\s*:\s*default-src\s+.*;', re.IGNORECASE), 
     'Missing or Weak Content Security Policy (CSP)', 'Medium', 'Define a strict CSP to prevent unauthorized resource loading and mitigate XSS risks.'),
    
    # Insecure Transport Layer (HTTPS should be enforced)
    (re.compile(r'http\.server\.secure-port\s*=\s*8080', re.IGNORECASE), 
     'HTTP Connection Allowed', 'High', 'Ensure all connections enforce HTTPS with SSL/TLS configurations.'),

    # Default CORS Policy (Cross-Origin Resource Sharing) Exposure
    (re.compile(r'spring\.web\.cors\.allowed-origin-patterns\s*=\s*\*', re.IGNORECASE), 
     'CORS Policy Allows All Origins', 'High', 'Restrict CORS to only trusted domains. Avoid using wildcard (*) in production.'),
    
    # Disabled HTTPS or SSL/TLS (Check for property allowing HTTP)
    (re.compile(r'server\.ssl\.enabled\s*=\s*false', re.IGNORECASE), 
     'SSL/TLS Disabled', 'High', 'Enable SSL/TLS to ensure secure communication over HTTPS.'),
    
    # X-Frame-Options Header Missing or Set to Allow
    (re.compile(r'X-Frame-Options\s*:\s*ALLOW', re.IGNORECASE), 
     'X-Frame-Options Header Allows Embedding', 'Medium', 'Set X-Frame-Options header to DENY or SAMEORIGIN to prevent clickjacking.'),

    # Insecure H2 Console Exposure
    (re.compile(r'spring\.h2\.console\.enabled\s*=\s*true', re.IGNORECASE), 
     'Insecure H2 Console Exposure', 'High', 'Disable H2 console in production or secure with authentication.'),

    # Debugging Enabled (not for production)
    (re.compile(r'spring\.boot\.admin\.client\.enabled\s*=\s*true', re.IGNORECASE), 
     'Debugging Enabled in Production', 'High', 'Disable debug settings in production environments to avoid exposing internal information.'),
    
    # API Keys and Secrets
    (re.compile(r'(?i)(api[_-]?key|secret|token)[\s:=]+[\'"]?[\w-]{16,}[\'"]?'), 
     'Hardcoded API Key or Secret', 'High', 'Move secrets to environment variables.'),
    (re.compile(r'(?i)(aws[_-]?secret|aws[_-]?access[_-]?key|s3[_-]?bucket)[\s:=]+[\'"]?\w{20,}[\'"]?'), 
     'AWS Secret Key or S3 Bucket Exposure', 'High', 'Use environment variables to manage AWS keys.'),
    (re.compile(r'(?i)(github|gitlab|bitbucket|slack)[\s:=]+[\'"]?\w{20,}[\'"]?'), 
     'Hardcoded GitHub/GitLab/Bitbucket/Slack Token', 'High', 'Store tokens securely in environment variables.'),
    (re.compile(r'(?i)(firebase[_-]?api[_-]?key)[\s:=]+[\'"]?\w{24,}[\'"]?'), 
     'Firebase API Key Exposure', 'High', 'Store Firebase keys in secure environment variables.'),
    (re.compile(r'(?i)(gcp[_-]?secret|google[_-]?cloud)[\s:=]+[\'"]?\w{20,}[\'"]?'), 
     'Google Cloud Secret or API Key Exposure', 'High', 'Move Google Cloud keys to environment variables.'),
    (re.compile(r'(?i)(azure[_-]?secret|azure[_-]?key)[\s:=]+[\'"]?\w{20,}[\'"]?'), 
     'Azure Secret Key Exposure', 'High', 'Store Azure secrets securely in environment variables.'),
     (re.compile(r'(?i)(auth|oauth|session|jwt)[\s:=]+[\'"]?[\w-]{16,}[\'"]?'), 
     'Sensitive Token Declaration', 'High', 'Track usage of authentication tokens to ensure safe handling.'),
    
    # Passwords and Authentication
    (re.compile(r'(?i)(password|passwd|pwd|auth)[\s:=]+[\'"]?.{6,}[\'"]?'), 
     'Hardcoded Password', 'High', 'Store passwords securely using environment variables or secrets manager.'),
    (re.compile(r'(?i)(session[_-]?id|sess[_-]?id)[\s:=]+[\'"]?[a-fA-F0-9]{32,}[\'"]?'), 
     'Hardcoded Session ID or Token', 'High', 'Store session IDs in secure session storage mechanisms.'),
    (re.compile(r'(?i)(oauth|bearer|access|refresh)[\s:=]+[\'"]?[\w-]{16,}[\'"]?'), 
     'Hardcoded OAuth/Bearer/Access/Refresh Token', 'High', 'Store tokens securely in environment variables.'),
    
    # Database Connection Strings
    (re.compile(r'jdbc:\w+://[^\s]+'), 
     'JDBC Connection String', 'High', 'Consider moving connection strings to environment variables.'),
    (re.compile(r'(?i)(mongodb|mysql|oracle|postgres|mssql):\/\/[^\s]+'), 
     'SQL Connection String', 'High', 'Use environment variables for database connection strings.'),
    (re.compile(r'(?i)(redis|memcached):\/\/[^\s]+'), 
     'Insecure Cache Connection String', 'Medium', 'Ensure cache connection strings are securely managed.'),
    
    # Encryption and Cryptographic Keys
    (re.compile(r'(?i)(private[_-]?key|public[_-]?key|pem|rsa_key)[\s:=]+[\'"]?.{32,}[\'"]?'), 
     'Hardcoded Cryptographic Key', 'High', 'Store cryptographic keys securely in environment variables or vaults.'),
    (re.compile(r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----'), 
     'Hardcoded Private Key', 'High', 'Store private keys in a secure secrets manager, not in code.'),
    (re.compile(r'(ssh-rsa|ssh-ed25519) [A-Za-z0-9+/]{100,}'), 
     'Potential SSH Public Key', 'Medium', 'Ensure public keys are not exposed in public repositories.'),
    (re.compile(r'(?i)(aes[_-]?key|des[_-]?key|3des[_-]?key|blowfish[_-]?key)[\s:=]+[\'"]?\w{16,}[\'"]?'), 
     'Hardcoded Symmetric Encryption Key', 'High', 'Store encryption keys securely in environment variables.'),
    
    # Personally Identifiable Information (PII)
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), 
     'Potential SSN', 'High', 'Remove or secure sensitive information like SSNs.'),
    (re.compile(r'\b\d{4}-\d{6}-\d{4}\b'), 
     'National ID or Tax ID Number', 'High', 'Ensure ID numbers are masked if not necessary.'),
    (re.compile(r'(?i)(dob|date[_-]?of[_-]?birth)[\s:=]+[\'"]?\d{4}-\d{2}-\d{2}[\'"]?'), 
     'Hardcoded Date of Birth', 'High', 'Avoid storing PII directly in code; use secure data handling practices.'),
    (re.compile(r'(?i)(phone[_-]?number|contact)[\s:=]+[\'"]?\+?\d{1,3}?[-.\s]?\(?\d{1,4}?\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}[\'"]?'), 
     'Hardcoded Phone Number', 'Medium', 'Avoid exposing phone numbers directly; use secure contact storage.'),
    
    # Credit Card Numbers
    (re.compile(r'\b4[0-9]{12}(?:[0-9]{3})?\b'), 
     'Potential Credit Card Number (Visa)', 'High', 'Do not store credit card numbers directly; use a secure payment gateway.'),
    (re.compile(r'\b(5[1-5][0-9]{14})\b'), 
     'Potential Credit Card Number (MasterCard)', 'High', 'Do not store credit card numbers directly; use a secure payment gateway.'),
    (re.compile(r'\b3[47][0-9]{13}\b'), 
     'Potential Credit Card Number (American Express)', 'High', 'Do not store credit card numbers directly; use a secure payment gateway.'),
    (re.compile(r'\b6(?:011|5[0-9]{2})[0-9]{12}\b'), 
     'Potential Credit Card Number (Discover)', 'High', 'Do not store credit card numbers directly; use a secure payment gateway.'),
    
    # JWT Tokens
    (re.compile(r'ey[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+'), 
     'Hardcoded JWT Token', 'High', 'Avoid hardcoding JWT tokens; use secure session storage mechanisms.'),
    
    # URLs and Endpoints
    (re.compile(r'(?i)http:\/\/[^\s]+'), 
     'Insecure HTTP URL', 'Medium', 'Use HTTPS for secure connections.'),
    (re.compile(r'(?i)localhost:[0-9]{4,5}'), 
     'Localhost Debugging Endpoint', 'Low', 'Avoid exposing localhost debugging endpoints.'),
    (re.compile(r'(?i)(ftp|smb):\/\/[^\s]+'), 
     'FTP/SMB URL', 'Medium', 'Ensure secure protocols (e.g., HTTPS) are used instead of FTP/SMB.'),
    
    # Debugging and Development Information
    (re.compile(r'(?i)(debug|development)[\s:=]+(true|1)', re.IGNORECASE), 
     'Debug Mode Enabled', 'Medium', 'Ensure debug mode is disabled in production.'),
    (re.compile(r'(?i)(dev|test|sandbox|staging)[\s]*url[\s]*=[\s]*[\'"]http'), 
     'Development/Test URL', 'Low', 'Ensure production code does not contain non-production URLs.'),
    
    # IP Address Exposure
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), 
     'IP Address Exposure', 'Medium', 'Ensure IP addresses are masked or redacted if not necessary.'),
    (re.compile(r'(?i)whitelist[_-]?ip[\s:=]+[\'"]?(?:\d{1,3}\.){3}\d{1,3}[\'"]?'), 
     'Hardcoded IP Whitelist', 'Medium', 'Manage IP whitelists securely without hardcoding them.'),
    
    # Miscellaneous Sensitive Data and Information Disclosures
    (re.compile(r'(?i)(app[_-]?secret|app[_-]?id|client[_-]?id|client[_-]?secret)[\s:=]+[\'"]?[\w-]{16,}[\'"]?'), 
     'Hardcoded Application Secret', 'High', 'Move application secrets to environment variables.'),
    (re.compile(r'(?i)(smtp|mail|email|ftp|proxy)[\s]*:[\s]*\/\/[^\s]+'), 
     'SMTP/Email/FTP/Proxy URL Exposure', 'Medium', 'Consider moving email/FTP credentials to secure configurations.'),
    (re.compile(r'(?i)(crypto|jwt)[\s:=]+[\'"]?[\w-]{16,}[\'"]?'), 
     'Hardcoded Cryptographic Token', 'High', 'Store cryptographic tokens securely.'),
    (re.compile(r'(?i)(authorization[_-]?header|auth[_-]?header)[\s:=]+[\'"]?\w{16,}[\'"]?'), 
     'Hardcoded Authorization Header', 'High', 'Avoid hardcoding authorization headers; use secure configurations.'),
    (re.compile(r'(?i)(access[_-]?token|refresh[_-]?token)[\s:=]+[\'"]?[\w-]{16,}[\'"]?'), 
     'Hardcoded Access or Refresh Token', 'High', 'Store tokens securely in environment variables or secure storage.'),
    
    # Insecure Protocols and Deprecated Libraries
    (re.compile(r'(?i)openssl[\s:=]+\d\.\d\.[01]'), 
     'Deprecated OpenSSL Version', 'High', 'Update OpenSSL to a secure version (1.1 or higher).'),

    # HTTP Methods
    #(re.compile(r'\b(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD|TRACE|CONNECT|DEBUG)\b', re.IGNORECASE), 
     #'HTTP Method Found', 'Informational', 'Check if this method exposes sensitive endpoints or data.'),
    #(re.compile(r'(?i)(get|post|put|delete|patch|options|head|trace|connect|debug)[\s]*\(.+?\)', re.IGNORECASE), 
     #'HTTP Method Call Detected in Code', 'Informational', 'Review this HTTP call for security checks (authentication, authorization).'),

    # HTTP Methods with URL patterns
    #(re.compile(r'(?i)(get|post|put|delete|patch|options|head|trace|connect|debug)[\s]*\([\'"]?https?:\/\/[^\s]+[\'"]?\)', re.IGNORECASE), 
     #'HTTP Method with URL', 'Informational', 'Ensure the URL and method are secured and authorized.'),

     # Example regex for Spring Boot vulnerabilities (like exposing management endpoints)
    (re.compile(r'(?i)management\.endpoints\.web\.exposure\.include\s*=\s*\*'),
     'Exposed Management Endpoint', 'High', 'Restrict management endpoints to authorized users only.'),
    (re.compile(r'(?i)(spring\.data\.source\.username|spring\.data\.source\.password)[\s:=]+[\'"]?.+?[\'"]?'), 
     'Hardcoded Database Credentials in Spring Boot', 'High', 'Store credentials in environment variables.'),
    
    # Injection vulnerabilities
    (re.compile(r'(?i)(eval|exec|subprocess\.call|os\.system|ProcessBuilder)'),
     'Potential Command Injection', 'High', 'Avoid using unsafe functions for external commands.'),
    (re.compile(r'(?i)PreparedStatement[\s]*\(.+?[\s]*;'), 
     'SQL Injection via Dynamic Query', 'High', 'Use parameterized queries to prevent SQL injection.'),
    
    # Spring Boot Actuator and other framework-specific issues
    (re.compile(r'(?i)(spring\.boot\.admin|actuator|health|env|configprops|mappings|trace|loggers|heapdump|threaddump|metrics)'),
     'Potentially Exposed Spring Boot Actuator Endpoint', 'High', 'Secure actuator endpoints with authentication.'),
    
    # Control Flow Detection Patterns
    (re.compile(r'if\s*\(.*?auth.*?\)|if\s*\(.*?login.*?\)', re.IGNORECASE), 
     'Authentication/Authorization Check', 'Informational', 'Check if access is restricted to authenticated users.'),
    (re.compile(r'if\s*\(.*?isAdmin.*?\)|if\s*\(.*?role.*?\)', re.IGNORECASE), 
     'Role-Based Access Control Check', 'Informational', 'Ensure access control based on user roles is enforced.'),
    
    # Insecure Data Usage Patterns
    (re.compile(r'(print|console\.log|logger\.info|logger\.debug|logging\.info)\s*\(.*?(api[_-]?key|secret|token|password|passwd|jwt).*\)', re.IGNORECASE), 
     'Sensitive Data in Logs', 'High', 'Do not log sensitive data.'),
    (re.compile(r'fetch|requests\.get|requests\.post|http\.get|http\.post', re.IGNORECASE), 
     'Sensitive Data in External Requests', 'High', 'Check if sensitive data is being sent in external requests.'),
]


# Color map for severity levels
COLOR_MAP = {
    'High': Fore.RED + Style.BRIGHT,
    'Medium': Fore.YELLOW + Style.BRIGHT,
    'Low': Fore.GREEN + Style.BRIGHT,
    'Informational': Fore.BLUE
}

# Initialize cache for incremental scan
CACHE_FILE = 'scan_cache.txt'
IGNORE_LIST = ['node_modules', '.git', '__pycache__']

def calculate_file_hash(file_path):
    """Calculate MD5 hash of a file for change detection."""
    hasher = hashlib.md5()
    with open(file_path, 'rb') as f:
        hasher.update(f.read())
    return hasher.hexdigest()

def load_previous_hashes():
    """Load previously calculated hashes for incremental scan."""
    hashes = {}
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, 'r') as f:
            for line in f:
                file_path, file_hash = line.strip().split(',')
                hashes[file_path] = file_hash
    return hashes

def save_current_hashes(hashes):
    """Save current file hashes after scanning."""
    with open(CACHE_FILE, 'w') as f:
        for file_path, file_hash in hashes.items():
            f.write(f"{file_path},{file_hash}\n")

def scan_file(file_path: str, previous_hashes, current_hashes) -> List[Dict[str, str]]:
    """Scan a file for regex patterns and return matches with line number, content, severity, and fix suggestion."""
    matches = []
    file_hash = calculate_file_hash(file_path)
    current_hashes[file_path] = file_hash

    # Skip unchanged files
    if file_path in previous_hashes and previous_hashes[file_path] == file_hash:
        return matches

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            sensitive_vars = []  # Track sensitive variables for data flow analysis
            for line_number, line in enumerate(file, start=1):
                # Data Flow Analysis (Taint Tracking)
                for pattern, description, severity, fix_suggestion in PATTERNS:
                    if pattern.search(line):
                        if "Sensitive Data Declaration" in description:
                            # Track sensitive variable assignment
                            var_match = re.search(r'(\w+)\s*=', line)
                            if var_match:
                                sensitive_vars.append(var_match.group(1))
                        
                        elif "Sensitive Data in External Requests" in description:
                            # Check if any tracked sensitive variable is used in external requests
                            for var in sensitive_vars:
                                if var in line:
                                    matches.append({
                                        'file': file_path,
                                        'line': line_number,
                                        'content': line.strip(),
                                        'description': 'Sensitive Data Sent in External Request',
                                        'severity': 'High',
                                        'fix_suggestion': 'Ensure sensitive data is secured before external requests.',
                                        'snippet': get_code_snippet(file_path, line_number)
                                    })

                        elif "Sensitive Data in Logs" in description:
                            # Check if any tracked sensitive variable is used in logging
                            for var in sensitive_vars:
                                if var in line:
                                    matches.append({
                                        'file': file_path,
                                        'line': line_number,
                                        'content': line.strip(),
                                        'description': 'Sensitive Data Logged',
                                        'severity': 'High',
                                        'fix_suggestion': 'Do not log sensitive data.',
                                        'snippet': get_code_snippet(file_path, line_number)
                                    })

                        else:
                            snippet = get_code_snippet(file_path, line_number)
                            matches.append({
                                'file': file_path,
                                'line': line_number,
                                'content': line.strip(),
                                'description': description,
                                'severity': severity,
                                'fix_suggestion': fix_suggestion,
                                'snippet': snippet
                            })
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
    return matches

def get_code_snippet(file_path, line_number, context=3):
    """Return code snippet around a matched line for context."""
    snippet = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            lines = file.readlines()
            start = max(line_number - context - 1, 0)
            end = min(line_number + context, len(lines))
            snippet = ''.join(lines[start:end])
    except Exception as e:
        logging.error(f"Error getting snippet from {file_path}: {e}")
    return snippet

def scan_pom(file_path: str):
    """Parse pom.xml file to extract dependencies and log them with dependency tree analysis."""
    try:
        tree = etree.parse(file_path)
        dependencies = tree.xpath('//dependency')
        for dep in dependencies:
            group_id = dep.findtext('groupId', 'Unknown')
            artifact_id = dep.findtext('artifactId', 'Unknown')
            version = dep.findtext('version', 'Unknown')
            logging.info(f"Dependency in {file_path}: Group: {group_id}, Artifact: {artifact_id}, Version: {version}")
    except Exception as e:
        logging.error(f"Error parsing pom.xml file {file_path}: {e}")

def get_code_snippet(file_path, line_number, context=3):
    """Return code snippet around a matched line for context."""
    snippet = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            lines = file.readlines()
            start = max(line_number - context - 1, 0)
            end = min(line_number + context, len(lines))
            snippet = ''.join(lines[start:end])
    except Exception as e:
        logging.error(f"Error getting snippet from {file_path}: {e}")
    return snippet

def track_data_flow():
    results = []
    for file_path, var_data in sensitive_data_map.items():
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            lines = file.readlines()
            for var, start_line in var_data:
                for i, line in enumerate(lines[start_line:], start=start_line):
                    if var in line and re.search(r'(print|log|send|http)', line):
                        snippet = get_code_snippet(file_path, i)
                        results.append({
                            'file': file_path,
                            'line': i + 1,
                            'content': line.strip(),
                            'description': f'Sensitive data "{var}" potentially exposed in external request or logging',
                            'severity': 'High',
                            'fix_suggestion': 'Remove or secure the sensitive data before using in logs or external requests.',
                            'snippet': snippet
                        })
    return results

# At the beginning of scan_directory
def scan_directory(directory: str, previous_hashes):
    print(f"Scanning directory: {directory}")
    current_hashes = {}
    findings = []

    # Log each file being processed
    with ThreadPoolExecutor() as executor:
        futures = []
        for root, _, files in os.walk(directory):
            if any(ignored in root for ignored in IGNORE_LIST):
                continue
            for file in files:
                file_path = os.path.join(root, file)
                print(f"Scanning file: {file_path}")  # Log each file
                if file.endswith(('.java', '.properties', '.xml', '.py', '.js', '.yml', '.json')):
                    futures.append(executor.submit(scan_file, file_path, previous_hashes, current_hashes))

        for future in futures:
            findings.extend(future.result())

    save_current_hashes(current_hashes)
    findings.extend(track_data_flow())
    return findings

def export_to_csv(findings, filename="security_scan_report.csv"):
    """Export findings to a CSV report."""
    with open(filename, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["File", "Line", "Description", "Severity", "Fix Suggestion", "Code Snippet"])
        for finding in findings:
            writer.writerow([finding['file'], finding['line'], finding['description'], finding['severity'], finding['fix_suggestion'], finding['snippet']])

init(autoreset=True)  # Initialize colorama with auto-reset for colors

def print_findings(findings):
    for finding in findings:
        severity = finding.get('severity', '').upper()
        
        # Assign color and indicator based on severity
        if severity == "INFORMATIONAL":
            color = Fore.BLUE
            indicator = "[+]"
        elif severity == "LOW":
            color = Fore.GREEN
            indicator = "[-]"
        elif severity == "MEDIUM":
            color = Fore.YELLOW
            indicator = "[!]"
        elif severity == "HIGH":
            color = Fore.RED + Style.BRIGHT
            indicator = "[x]"
        else:
            color = Fore.WHITE
            indicator = "[?]"

        # Print findings with color and formatting
        print(f"{color}{indicator} {finding['description']}{Style.RESET_ALL}")
        print(f"{color}    - File: {finding['file']}{Style.RESET_ALL}")
        print(f"{color}    - Line: {finding['line']}{Style.RESET_ALL}")
        print(f"{color}    - Severity: {severity}{Style.RESET_ALL}")
        print(f"{color}    - Suggested Fix: {finding.get('fix_suggestion', 'N/A')}{Style.RESET_ALL}")
        print(f"{color}    - Code Snippet: {finding.get('snippet', '').strip()}{Style.RESET_ALL}")
        print()  # Blank line for readability

def export_to_html(findings, filename="security_scan_report.html"):
    """Export findings to an HTML report with sorting, pagination, search, filter, collapsible sections, and logo."""
    unique_findings = {}
    for finding in findings:
        key = (finding['file'], finding['line'], finding['description'])
        if key not in unique_findings:
            unique_findings[key] = {
                "finding": finding,
                "count": 1,
                "locations": [(finding['file'], finding['line'])]
            }
        else:
            unique_findings[key]["count"] += 1
            unique_findings[key]["locations"].append((finding['file'], finding['line']))

    sorted_findings = defaultdict(list)
    for unique_finding in unique_findings.values():
        sorted_findings[unique_finding["finding"]['severity']].append(unique_finding)

    # HTML template with collapsible sections and color mapping
    html_template = Template("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>GuardTrex Security Scan Report</title>
        <style>
            body { font-family: Arial, sans-serif; color: #333; line-height: 1.6; }
            header { display: flex; align-items: center; padding: 20px; border-bottom: 2px solid #ddd; }
            .logo { font-size: 24px; font-weight: bold; color: #333; }
            .report-title { font-size: 28px; color: #555; margin-left: auto; }
            .controls { display: flex; justify-content: space-between; padding: 20px; }
            .search-box { flex: 1; padding: 10px; font-size: 16px; }
            .filter, .sort { margin-left: 10px; padding: 10px; font-size: 16px; }
            .summary { padding: 20px; text-align: center; font-size: 18px; background-color: #f9f9f9; border-bottom: 2px solid #ddd; }
            .summary-item { margin: 5px; font-weight: bold; }
            .severity-section { margin: 20px 0; border: 1px solid #ddd; border-radius: 5px; overflow: hidden; }
            .section-title { padding: 15px; font-size: 20px; cursor: pointer; display: flex; align-items: center; justify-content: space-between; }
            .high { background-color: #f8d7da; color: #721c24; }
            .medium { background-color: #fff3cd; color: #856404; }
            .low { background-color: #d4edda; color: #155724; }
            .informational { background-color: #d1ecf1; color: #0c5460; }
            .findings-content { display: none; padding: 10px; animation: slide-down 0.3s ease-out; }
            .finding { padding: 10px; border: 1px solid #ddd; margin-bottom: 10px; border-radius: 5px; background-color: #f9f9f9; }
            .file, .line, .description, .fix, .duplicate-label { margin: 5px 0; }
            .expandable { cursor: pointer; color: #007bff; text-decoration: underline; }
            pre { background: #f4f4f4; padding: 10px; border-radius: 5px; overflow-x: auto; font-family: monospace; white-space: pre-wrap; }
            .pagination { text-align: center; margin: 20px; }
            .pagination button { margin: 0 5px; padding: 8px 16px; cursor: pointer; font-size: 16px; }
            .hidden { display: none; }

            /* Icon styles */
            .icon { margin-right: 8px; font-weight: bold; }

            /* Animation for collapsible sections */
            @keyframes slide-down {
                from { opacity: 0; max-height: 0; }
                to { opacity: 1; max-height: 1000px; }
            }
        </style>
    </head>
    <body>
        <header>
            <div class="logo">GuardTrex</div>
            <h1 class="report-title">Security Scan Report</h1>
        </header>

        <div class="summary">
            <span class="summary-item high"><span class="icon">🔴</span>High: {{ sorted_findings['High'] | length }}</span>
            <span class="summary-item medium"><span class="icon">🟠</span>Medium: {{ sorted_findings['Medium'] | length }}</span>
            <span class="summary-item low"><span class="icon">🟢</span>Low: {{ sorted_findings['Low'] | length }}</span>
            <span class="summary-item informational"><span class="icon">🔵</span>Informational: {{ sorted_findings['Informational'] | length }}</span>
        </div>
        
        <div class="controls">
            <input type="text" id="search" class="search-box" placeholder="Search by file, description, or fix...">
            <select id="severity-filter" class="filter" title="Filter by severity">
                <option value="all">All Severities</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
                <option value="Informational">Informational</option>
            </select>
            <select id="sort" class="sort" title="Sort findings">
                <option value="severity">Sort by Severity</option>
                <option value="alphabetical">Sort Alphabetically</option>
            </select>
        </div>

        <div id="findings-container">
            {% for severity in ['High', 'Medium', 'Low', 'Informational'] %}
            <div class="severity-section {{ severity.lower() }}">
                <div class="section-title {{ severity.lower() }}" onclick="toggleSection(this)">
                    <span><span class="icon"></span>{{ severity.upper() }} SEVERITY</span>
                </div>
                <div class="findings-content">
                    {% for unique_finding in sorted_findings[severity] %}
                    <div class="finding" data-severity="{{ severity }}" data-description="{{ unique_finding['finding']['description'] }}" data-count="{{ unique_finding['count'] }}">
                        <div class="file"><strong>File:</strong> {{ unique_finding['finding']['file'] }} <span class="duplicate-label">(Found {{ unique_finding['count'] }} times)</span></div>
                        <div class="line"><strong>Line:</strong> {{ unique_finding['finding']['line'] }}</div>
                        <div class="description"><strong>Description:</strong> {{ unique_finding['finding']['description'] }}</div>
                        <div class="fix"><strong>Suggested Fix:</strong> {{ unique_finding['finding']['fix_suggestion'] }}</div>
                        <div class="expandable" onclick="toggleSnippet(this)">Show Code Snippet</div>
                        <pre class="code-snippet hidden">{{ unique_finding['finding']['snippet'] }}</pre>
                    </div>
                    {% else %}
                    <div class="finding">No findings for this severity.</div>
                    {% endfor %}
                </div>
            </div>
            {% endfor %}
        </div>

        <div class="pagination">
            <button onclick="prevPage()">Previous</button>
            <span id="page-info">Page <span id="current-page">1</span> of <span id="total-pages">1</span></span>
            <button onclick="nextPage()">Next</button>
        </div>

        <script>
            let currentPage = 1;
            const findingsPerPage = 10;
            const findings = Array.from(document.querySelectorAll('.finding'));

            function updatePagination() {
                const totalPages = Math.ceil(findings.filter(f => !f.classList.contains('hidden')).length / findingsPerPage);
                document.getElementById('total-pages').innerText = totalPages || 1;
                document.getElementById('current-page').innerText = currentPage;
            }

            function showPage(page) {
                const start = (page - 1) * findingsPerPage;
                const end = start + findingsPerPage;

                findings.forEach((finding, index) => {
                    finding.classList.toggle('hidden', index < start || index >= end);
                });
                updatePagination();
            }

            function applyFilters() {
                const searchQuery = document.getElementById('search').value.toLowerCase();
                const severityFilter = document.getElementById('severity-filter').value;

                findings.forEach(finding => {
                    const matchesSearch = finding.querySelector('.description').innerText.toLowerCase().includes(searchQuery);
                    const matchesSeverity = severityFilter === 'all' || finding.dataset.severity === severityFilter;
                    finding.classList.toggle('hidden', !(matchesSearch && matchesSeverity));
                });

                currentPage = 1;
                showPage(currentPage);
            }

            function toggleSnippet(element) {
                const snippet = element.nextElementSibling;
                snippet.classList.toggle('hidden');
                element.textContent = snippet.classList.contains('hidden') ? 'Show Code Snippet' : 'Hide Code Snippet';
            }

            function toggleSection(element) {
                const content = element.nextElementSibling;
                content.style.display = content.style.display === 'none' ? 'block' : 'none';
            }

            document.getElementById('search').addEventListener('input', applyFilters);
            document.getElementById('severity-filter').addEventListener('change', applyFilters);

            // Initialize
            applyFilters();
            showPage(currentPage);
        </script>
    </body>
    </html>
    """)

    rendered_html = html_template.render(sorted_findings=sorted_findings)

    # Write to file with UTF-8 encoding to handle Unicode characters
    with open(filename, 'w', encoding='utf-8') as file:
        file.write(rendered_html)

    print(f"HTML report generated: {filename}")

def main():
    """Main function to parse CLI arguments and run the scan."""
    parser = argparse.ArgumentParser(description="Scan codebase for security vulnerabilities.")
    parser.add_argument('directory', type=str, help='Path to the directory to scan')
    parser.add_argument('--format', choices=['html', 'csv', 'both'], default='both', help='Output report format')
    args = parser.parse_args()

    previous_hashes = load_previous_hashes()
    findings = scan_directory(args.directory, previous_hashes)

    # Print findings in console for quick view
    print_findings(findings)
    print(f"Total findings: {len(findings)}")

    # Export findings based on selected format
    if args.format == 'csv' or args.format == 'both':
        export_to_csv(findings)
        print("CSV report generated as 'security_scan_report.csv'.")

    if args.format == 'html' or args.format == 'both':
        export_to_html(findings)
        print("HTML report generated as 'security_scan_report.html'.")

    print("Scan complete. Reports are saved in the specified format(s).")

if __name__ == "__main__":
    main()

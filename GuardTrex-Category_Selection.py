import os
import re
import logging
import hashlib
import csv
import html
import argparse
from colorama import Fore, Style, init
from lxml import etree
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from collections import defaultdict
from jinja2 import Template

# Initialize colorama for color-coded console output
init(autoreset=True)

# Configure logging
logging.basicConfig(
    filename='security_scan.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


# Constants
CACHE_FILE = 'scan_cache.txt'
IGNORE_LIST = ['node_modules', '.git', '__pycache__']
SCANNABLE_EXTENSIONS = ('.java', '.properties', '.xml', '.py', '.js', '.yml', '.json')
GUARDTREX_ASCII = """
   ____ _   _   _    ____  ____ _____ ____  _______  __
  / ___| | | | / \  |  _ \|  _ \_   _|  _ \| ____\ \/ /
 | |  _| | | |/ _ \ | |_) | | | || | | |_) |  _|  \  /
 | |_| | |_| / ___ \|  _ <| |_| || | |  _ <| |___ /  \
  \____|\___/_/   \_\_| \_\____/ |_| |_| \_\_____/_/\_\
                                                       
"""

# Initialize cache for incremental scan
sensitive_data_map = {}

# Define regex patterns with descriptions, severity, and automatic fix suggestions
PATTERNS = {
    "Actuator Endpoints": [
        (re.compile(r'management\.endpoints\.web\.exposure\.include\s*=\s*\*', re.IGNORECASE), 
         'All Actuator Endpoints Exposed', 'High', 'Limit exposure of Actuator endpoints to necessary endpoints only, and secure with authentication.'),
        (re.compile(r'management\.endpoints\.web\.exposure\.include\s*=\s*(health|info)', re.IGNORECASE), 
         'Exposed Actuator Endpoint (health/info)', 'Medium', 'Ensure that exposed endpoints are not disclosing sensitive information.')
    ],
    
    "CSRF Protection": [
        (re.compile(r'spring\.security\.csrf\.enabled\s*=\s*false', re.IGNORECASE), 
         'CSRF Protection Disabled', 'High', 'Enable CSRF protection for all forms or secure endpoints requiring stateful interactions.')
    ],
    
    "Password Storage": [
        (re.compile(r'spring\.data\.source\.password\s*=\s*[\'"]?[a-zA-Z0-9]*[\'"]?', re.IGNORECASE), 
         'Insecure Password Storage', 'High', 'Store database credentials in a secure configuration provider or environment variable.')
    ],
    
    "HTTPS Enforcement": [
        (re.compile(r'http\.server\.secure-port\s*=\s*8080', re.IGNORECASE), 
         'HTTP Connection Allowed', 'High', 'Ensure all connections enforce HTTPS with SSL/TLS configurations.'),
        (re.compile(r'server\.ssl\.enabled\s*=\s*false', re.IGNORECASE), 
         'SSL/TLS Disabled', 'High', 'Enable SSL/TLS to ensure secure communication over HTTPS.')
    ],
    
    "Response Headers Security": [
        (re.compile(r'Content-Security-Policy\s*:\s*default-src\s+.*;', re.IGNORECASE), 
         'Missing or Weak Content Security Policy (CSP)', 'Medium', 'Define a strict CSP to prevent unauthorized resource loading and mitigate XSS risks.'),
        (re.compile(r'spring\.web\.cors\.allowed-origin-patterns\s*=\s*\*', re.IGNORECASE), 
         'CORS Policy Allows All Origins', 'High', 'Restrict CORS to only trusted domains. Avoid using wildcard (*) in production.')
    ],
    
    "H2 Console": [
        (re.compile(r'spring\.h2\.console\.enabled\s*=\s*true', re.IGNORECASE), 
         'Insecure H2 Console Exposure', 'High', 'Disable H2 console in production or secure with authentication.')
    ],
    
    "Debugging Enablement": [
        (re.compile(r'spring\.boot\.admin\.client\.enabled\s*=\s*true', re.IGNORECASE), 
         'Debugging Enabled in Production', 'High', 'Disable debug settings in production environments to avoid exposing internal information.'),
        (re.compile(r'spring\.devtools\.restart\.enabled\s*=\s*true', re.IGNORECASE), 
         'Spring Boot Devtools Enabled', 'Medium', 'Disable Devtools in production as it can expose sensitive data and increase resource usage.'),
        (re.compile(r'logging\.level\..*\s*=\s*DEBUG', re.IGNORECASE), 
         'Verbose Logging Enabled', 'Medium', 'Set logging level to WARN or ERROR in production to avoid logging sensitive information.'),
        (re.compile(r'display_errors\s*=\s*On', re.IGNORECASE), 
         'PHP Display Errors Enabled', 'High', 'Set display_errors=Off in production to avoid exposing sensitive server information.'),
        (re.compile(r'console\.log\(', re.IGNORECASE), 
         'Console Logging in Node.js', 'Medium', 'Avoid using console.log in production; use structured logging with appropriate levels.'),
        (re.compile(r'APP_DEBUG\s*=\s*true', re.IGNORECASE), 
         'Debug Mode Enabled in Laravel', 'High', 'Disable APP_DEBUG in production to prevent detailed error messages.')
    ],
    
    "API Keys and Secrets": [
        (re.compile(r'(?i)(api[_-]?secret|secret[_-]?token)[\s:=]+[\'"]?.{16,}[\'"]?'), 
         'Hardcoded API Secret Token', 'High', 'Store API secret tokens in secure environment variables.'),
        (re.compile(r'(?i)client[_-]?secret[\s:=]+[\'"]?.{16,}[\'"]?'), 
         'Hardcoded OAuth Client Secret', 'High', 'Store OAuth client secrets securely in environment variables.'),
        (re.compile(r'(?i)(encryption[_-]?key|aes[_-]?key)[\s:=]+[\'"]?.{16,}[\'"]?'), 
         'Hardcoded Encryption Key', 'High', 'Avoid hardcoding encryption keys; use secure key management solutions.')
    ],
    
    "Database Connection Strings": [
        (re.compile(r'(?i)(db[_-]?password|database[_-]?password)[\s:=]+[\'"]?.{6,}[\'"]?'), 
         'Hardcoded Database Password', 'High', 'Store database passwords securely in environment variables.'),
        (re.compile(r'mongodb:\/\/(.*?):(.*?)@', re.IGNORECASE), 
         'MongoDB Connection String with Credentials', 'High', 'Store MongoDB credentials securely in environment variables.')
    ],
    
    "Cryptography Affairs": [
        (re.compile(r'(?i)(private[_-]?key|public[_-]?key|pem|rsa_key)[\s:=]+[\'"]?.{32,}[\'"]?'), 
         'Hardcoded Cryptographic Key', 'High', 'Store cryptographic keys securely in environment variables or vaults.'),
        (re.compile(r'-----BEGIN RSA PRIVATE KEY-----', re.IGNORECASE), 
         'Hardcoded RSA Private Key', 'High', 'Store RSA private keys in a secure vault rather than embedding them in code.')
    ],
    
    "Personally Identifiable Information (PII)": [
        (re.compile(r'\b\d{1,2}[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])\d{7}\b'), 
         'Potential Egyptian National ID Number', 'High', 'Ensure that Egyptian National IDs are securely stored and masked when displayed.'),
        (re.compile(r'\b[A-Z]{1}[0-9]{8}\b'), 
         'Potential Egyptian Passport Number', 'High', 'Avoid storing passport numbers directly; secure them if necessary.')
    ],
    
    "Credit Card Numbers": [
        (re.compile(r'\b5[1-5][0-9]{14}\b'), 
         'Potential Credit Card Number (MasterCard)', 'High', 'Do not store credit card numbers directly; use a secure payment gateway.'),
        (re.compile(r'\b3[47][0-9]{13}\b'), 
         'Potential Credit Card Number (American Express)', 'High', 'Do not store credit card numbers directly; use a secure payment gateway.')
    ],
    
    "Injection Vulnerabilities": [
        (re.compile(r'(?i)(os\.system|subprocess\.popen|subprocess\.call|subprocess\.run|eval|exec|popen|shell_exec|system|passthru|ProcessBuilder)', re.IGNORECASE), 
         'Potential Command Injection (Dangerous Function Usage)', 'High', 'Avoid using potentially dangerous functions that can lead to command injection.'),
        (re.compile(r'(execute|query|prepare|executeQuery|executeUpdate)\s*\(.*[+].*\)', re.IGNORECASE), 
         'Potential SQL Injection (Concatenated SQL Commands)', 'High', 'Avoid concatenating user inputs in SQL commands; use parameterized queries.')
    ],
    
    "Cross-Site Scripting (XSS)": [
        (re.compile(r'<script\b[^>]*>(.*?)<\/script>', re.IGNORECASE), 
         'Potential XSS (Inline JavaScript)', 'High', 'Avoid directly including user input in inline JavaScript; use proper encoding or sanitization.'),
        (re.compile(r'<.*?\bon\w+\s*=\s*["\'].*?\+.*?["\'].*?>', re.IGNORECASE), 
         'Potential XSS (Event Handler in HTML Tag)', 'High', 'Avoid using untrusted data in HTML event handlers. Sanitize and encode data before insertion.')
    ],
    
    "Sensitive Data in Logs": [
        (re.compile(r'(print|console\.log|logger\.info|logger\.debug|logging\.info)\s*\(.*?(api[_-]?key|secret|token|password|passwd|jwt).*\)', re.IGNORECASE), 
         'Sensitive Data in Logs', 'High', 'Do not log sensitive data.')
    ],
    
    "Insecure URLs and Endpoints": [
        (re.compile(r'(?i)http:\/\/[^\s]+'), 
         'Insecure HTTP URL', 'Medium', 'Use HTTPS for secure connections.')
    ],
    
    "Debugging and Development Information": [
        (re.compile(r'(?i)(debug|development)[\s:=]+(true|1)', re.IGNORECASE), 
         'Debug Mode Enabled', 'Medium', 'Ensure debug mode is disabled in production.')
    ],
    
    "IP Address Exposure": [
        (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), 
         'IP Address Exposure', 'Medium', 'Ensure IP addresses are masked or redacted if not necessary.')
    ]
}


# Color map for severity levels
COLOR_MAP = {
    'High': Fore.RED + Style.BRIGHT,
    'Medium': Fore.YELLOW + Style.BRIGHT,
    'Low': Fore.GREEN + Style.BRIGHT,
    'Informational': Fore.BLUE
}

def calculate_file_hash(file_path):
    """Calculate MD5 hash of a file for change detection, handling errors gracefully."""
    hasher = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            hasher.update(f.read())
        return hasher.hexdigest()
    except Exception as e:
        logging.error(f"Error calculating hash for {file_path}: {e}")
    return None

def load_previous_hashes():
    """Load previously calculated hashes for incremental scan, handling file errors."""
    hashes = {}
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                for line in f:
                    try:
                        file_path, file_hash = line.strip().split(',')
                        hashes[file_path] = file_hash
                    except ValueError:
                        logging.warning(f"Invalid line format in cache file: {line.strip()}")
        except Exception as e:
            logging.error(f"Error loading hashes from cache file {CACHE_FILE}: {e}")
    return hashes

def save_current_hashes(hashes):
    """Save current file hashes after scanning, handling file errors."""
    try:
        with open(CACHE_FILE, 'w') as f:
            for file_path, file_hash in hashes.items():
                f.write(f"{file_path},{file_hash}\n")
    except Exception as e:
        logging.error(f"Error saving hashes to cache file {CACHE_FILE}: {e}")

def display_category_menu():
    """Display vulnerability categories and capture user selection for scan customization."""
    print(Fore.CYAN + "\nSelect Vulnerability Categories to Scan:")
    categories = list(PATTERNS.keys())
    for idx, category in enumerate(categories, start=1):
        print(Fore.YELLOW + f"{idx}. {category}")
    print(Fore.YELLOW + "0. Select All Categories")

    selected_categories = input(Fore.CYAN + "\nEnter category numbers separated by commas (e.g., 1,3,5): ").strip()
    selected_indices = [int(x.strip()) for x in selected_categories.split(',') if x.strip().isdigit()]

    if 0 in selected_indices:
        return categories
    else:
        return [categories[idx - 1] for idx in selected_indices if 1 <= idx <= len(categories)]

def get_patterns_by_selected_categories(selected_categories):
    """Fetch regex patterns for user-selected categories."""
    selected_patterns = []
    for category in selected_categories:
        selected_patterns.extend(PATTERNS[category])
    return selected_patterns

def get_code_snippet(file_path, line_number, context=3):
    """Return code snippet around a matched line for context, handling file errors."""
    snippet = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            lines = file.readlines()
            start = max(line_number - context - 1, 0)
            end = min(line_number + context, len(lines))
            snippet = ''.join(lines[start:end])
    except Exception as e:
        logging.error(f"Error getting snippet from {file_path} at line {line_number}: {e}")
    return snippet

def scan_file(file_path: str, previous_hashes, current_hashes, selected_patterns) -> List[Dict[str, str]]:
    """Scan a file using selected regex patterns."""
    matches = []
    file_hash = calculate_file_hash(file_path)
    current_hashes[file_path] = file_hash

    # Skip unchanged files
    if file_path in previous_hashes and previous_hashes[file_path] == file_hash:
        return matches

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line_number, line in enumerate(file, start=1):
                for pattern, description, severity, fix_suggestion in selected_patterns:
                    if pattern.search(line):
                        matches.append({
                            'file': file_path,
                            'line': line_number,
                            'content': line.strip(),
                            'description': description,
                            'severity': severity,
                            'fix_suggestion': fix_suggestion,
                            'snippet': get_code_snippet(file_path, line_number)
                        })
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
    return matches

def scan_directory(directory: str, previous_hashes, selected_patterns):
    """Scan a directory with selected patterns."""
    print(f"Scanning directory: {directory}")
    current_hashes = {}
    findings = []

    with ThreadPoolExecutor() as executor:
        futures = []
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if file.endswith(('.java', '.properties', '.xml', '.py', '.js', '.yml', '.json')):
                    futures.append(executor.submit(scan_file, file_path, previous_hashes, current_hashes, selected_patterns))

        for future in futures:
            findings.extend(future.result())

    save_current_hashes(current_hashes)
    findings.extend(track_data_flow())
    return findings

def track_data_flow():
    """Track sensitive data flow and check for exposure in logs or external requests, with error handling."""
    results = []
    for file_path, var_data in sensitive_data_map.items():
        try:
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
        except FileNotFoundError:
            logging.error(f"File not found for data flow analysis: {file_path}")
        except PermissionError:
            logging.error(f"Permission denied when reading file for data flow analysis: {file_path}")
        except Exception as e:
            logging.error(f"Unexpected error during data flow analysis in file {file_path}: {e}")
    return results

def export_to_csv(findings, filename="security_scan_report.csv"):
    """Export findings to a CSV report."""
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["File", "Line", "Description", "Severity", "Fix Suggestion", "Code Snippet"])
            for finding in findings:
                writer.writerow([
                    finding.get('file', 'N/A'), 
                    finding.get('line', 'N/A'), 
                    finding.get('description', 'N/A'), 
                    finding.get('severity', 'N/A'), 
                    finding.get('fix_suggestion', 'N/A'), 
                    finding.get('snippet', '').strip()
                ])
        logging.info(f"Findings successfully exported to {filename}")
    except Exception as e:
        logging.error(f"Error exporting findings to CSV file {filename}: {e}")

def export_to_html(findings, filename="security_scan_report.html"):
    """Export findings to an HTML report with sorting, pagination, search, filter, and collapsible sections, with error handling and XSS protection."""
    
    unique_findings = {}
    try:
        # Process findings for duplicates
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

        # Organize findings by severity level
        sorted_findings = defaultdict(list)
        for unique_finding in unique_findings.values():
            severity = unique_finding["finding"].get('severity', 'Informational')
            sorted_findings[severity].append(unique_finding)

        # HTML template for report generation
        html_template = Template("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>GuardTrex Security Scan Report</title>
            <style>
                body { font-family: Arial, sans-serif; color: #333; line-height: 1.6; background-color: #f4f4f9; }
                header { display: flex; align-items: center; padding: 20px; border-bottom: 2px solid #ddd; }
                .logo { font-size: 24px; font-weight: bold; color: #333; }
                .report-title { font-size: 28px; color: #555; margin-left: auto; }
                .summary { padding: 20px; text-align: center; font-size: 18px; background-color: #f9f9f9; border-bottom: 2px solid #ddd; }
                .summary-item { margin: 5px; font-weight: bold; }
                .severity-section { margin: 20px 0; border: 1px solid #ddd; border-radius: 5px; }
                .section-title { padding: 15px; font-size: 20px; cursor: pointer; display: flex; align-items: center; justify-content: space-between; font-weight: bold; }
                .section-title::after { content: '▼'; margin-left: 8px; font-size: 14px; }
                .section-title.collapsed::after { content: '▶'; }
                .high { background-color: #f8d7da; color: #721c24; }
                .medium { background-color: #fff3cd; color: #856404; }
                .low { background-color: #d4edda; color: #155724; }
                .informational { background-color: #d1ecf1; color: #0c5460; }
                .findings-content { display: none; padding: 10px; }
                .finding { padding: 10px; border: 1px solid #ddd; margin-bottom: 10px; border-radius: 5px; background-color: #f9f9f9; }
                .file, .line, .description, .fix, .duplicate-label { margin: 5px 0; }
                .expandable { cursor: pointer; color: #007bff; text-decoration: underline; }
                pre.sandboxed { background: #f4f4f4; padding: 10px; border-radius: 5px; overflow-x: auto; font-family: monospace; white-space: pre-wrap; color: #444; }
                .pagination { text-align: center; margin: 20px; }
                .pagination button { margin: 0 5px; padding: 8px 16px; cursor: pointer; font-size: 16px; }
                .hidden { display: none; }

                /* Accessibility and UI enhancements */
                .search-box { width: 80%; padding: 10px; font-size: 16px; margin: 20px; }
                .filter, .sort { margin-left: 10px; padding: 10px; font-size: 16px; }
                .controls { display: flex; justify-content: space-between; padding: 20px; }
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
                <input type="text" id="search" class="search-box" placeholder="Search by file, description, or fix..." aria-label="Search findings">
                <select id="severity-filter" class="filter" aria-label="Filter by severity">
                    <option value="all">All Severities</option>
                    <option value="High">High</option>
                    <option value="Medium">Medium</option>
                    <option value="Low">Low</option>
                    <option value="Informational">Informational</option>
                </select>
                <select id="sort" class="sort" aria-label="Sort findings">
                    <option value="severity">Sort by Severity</option>
                    <option value="alphabetical">Sort Alphabetically</option>
                </select>
            </div>

            <div id="findings-container">
                {% for severity in ['High', 'Medium', 'Low', 'Informational'] %}
                <div class="severity-section {{ severity.lower() }}">
                    <div class="section-title {{ severity.lower() }}" onclick="toggleSection(this)">
                        <span>{{ severity.upper() }} SEVERITY</span>
                    </div>
                    <div class="findings-content">
                        {% for unique_finding in sorted_findings[severity] %}
                        <div class="finding" data-severity="{{ severity }}" data-description="{{ unique_finding['finding']['description'] }}" data-count="{{ unique_finding['count'] }}">
                            <div class="file"><strong>File:</strong> {{ unique_finding['finding']['file'] | e }}</div>
                            <div class="line"><strong>Line:</strong> {{ unique_finding['finding']['line'] }}</div>
                            <div class="description"><strong>Description:</strong> {{ unique_finding['finding']['description'] | e }}</div>
                            <div class="fix"><strong>Suggested Fix:</strong> {{ unique_finding['finding']['fix_suggestion'] | e }}</div>
                            <div class="expandable" onclick="toggleSnippet(this)">Show Code Snippet</div>
                            <pre class="code-snippet sandboxed hidden">{{ unique_finding['finding']['snippet'] }}</pre>
                        </div>
                        {% else %}
                        <div class="finding">No findings for this severity.</div>
                        {% endfor %}
                    </div>
                </div>
                {% endfor %}
            </div>

            <div class="pagination">
                <button onclick="prevPage()" aria-label="Previous page">Previous</button>
                <span id="page-info">Page <span id="current-page">1</span> of <span id="total-pages">1</span></span>
                <button onclick="nextPage()" aria-label="Next page">Next</button>
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
                    element.classList.toggle('collapsed');
                }

                document.getElementById('search').addEventListener('input', applyFilters);
                document.getElementById('severity-filter').addEventListener('change', applyFilters);

                applyFilters();
                showPage(currentPage);
            </script>
        </body>
        </html>
        """)


        # Escape potentially harmful characters in findings before rendering
        for finding in findings:
            finding['file'] = html.escape(finding.get('file', 'Unknown file'))
            finding['description'] = html.escape(finding.get('description', 'No description provided'))
            finding['fix_suggestion'] = html.escape(finding.get('fix_suggestion', 'N/A'))
            finding['snippet'] = html.escape(finding.get('snippet', '').strip())

        rendered_html = html_template.render(sorted_findings=sorted_findings)

        # Write the rendered HTML to a file
        with open(filename, 'w', encoding='utf-8') as file:
            file.write(rendered_html)
        
        print(f"HTML report generated: {filename}")
        logging.info(f"HTML report successfully generated: {filename}")
    except PermissionError:
        logging.error(f"Permission denied when trying to write to HTML file: {filename}")
        print("Error: Permission denied when trying to write the HTML report.")
    except Exception as e:
        logging.error(f"Unexpected error exporting findings to HTML file {filename}: {e}")
        print("An unexpected error occurred while generating the HTML report.")

def print_findings(findings):
    """Print findings to the console with color coding based on severity."""
    for finding in findings:
        try:
            severity = finding.get('severity', 'UNKNOWN').upper()
            color = COLOR_MAP.get(severity, Fore.WHITE)
            indicator = {"High": "[x]", "Medium": "[!]", "Low": "[-]", "Informational": "[+]"}[severity]
            print(f"{color}{indicator} {finding.get('description', 'No description provided')}")
            print(f"{color}    - File: {finding.get('file', 'Unknown file')}")
            print(f"{color}    - Line: {finding.get('line', 'N/A')}")
            print(f"{color}    - Severity: {severity}")
            print(f"{color}    - Suggested Fix: {finding.get('fix_suggestion', 'N/A')}")
            print(f"{color}    - Code Snippet: {finding.get('snippet', '').strip()}\n")
        except Exception as e:
            logging.error(f"Error printing finding: {e}")

GUARDTREX_ASCII = """
   ____ _   _   _    ____  ____ _____ ____  _______  __
  / ___| | | | / \  |  _ \|  _ \_   _|  _ \| ____\ \/ /
 | |  _| | | |/ _ \ | |_) | | | || | | |_) |  _|  \  / 
 | |_| | |_| / ___ \|  _ <| |_| || | |  _ <| |___ /  \ 
  \____|\___/_/   \_\_| \_\____/ |_| |_| \_\_____/_/\_\
                                                       
"""

# Display Category Selection Menu
def display_category_menu():
    print(Fore.CYAN + "\nSelect Vulnerability Categories to Scan:")
    categories = list(PATTERNS.keys())
    for idx, category in enumerate(categories, start=1):
        print(Fore.YELLOW + f"{idx}. {category}")
    print(Fore.YELLOW + "0. Select All Categories")

    # Get user selection
    selected_categories = input(Fore.CYAN + "\nEnter the category numbers separated by commas (e.g., 1,3,5): ").strip()
    selected_indices = [int(x.strip()) for x in selected_categories.split(',') if x.strip().isdigit()]
    
    # Map indices to category names
    if 0 in selected_indices:
        return categories
    else:
        return [categories[idx - 1] for idx in selected_indices if 1 <= idx <= len(categories)]

# Fetch patterns for the selected categories
def get_patterns_by_selected_categories(selected_categories):
    selected_patterns = []
    for category in selected_categories:
        selected_patterns.extend(PATTERNS[category])
    return selected_patterns

def main():
    print(Fore.CYAN + Style.BRIGHT + GUARDTREX_ASCII)
    print(Fore.CYAN + Style.BRIGHT + "=" * 55)
    print(Fore.CYAN + Style.BRIGHT + "      Welcome to GuardTrex - Security Code Scanner")
    print(Fore.CYAN + Style.BRIGHT + "=" * 55)

    parser = argparse.ArgumentParser(
        description="GuardTrex - Scan codebase for security vulnerabilities.",
        epilog="Example usage: python GuardTrex.py <directory> --format both"
    )
    parser.add_argument('directory', type=str, nargs='?', help='Path to the directory to scan.')
    parser.add_argument('--format', choices=['html', 'csv', 'both'], default='both', help='Output report format (default: both)')
    parser.add_argument('--interactive', action='store_true', help='Run in interactive mode for a guided user journey.')
    args = parser.parse_args()

    # Interactive Mode for User Guidance
    if args.interactive:
        # Directory Selection
        if not args.directory:
            print(Fore.CYAN + "Step 1: Select Directory to Scan")
            args.directory = input(Fore.YELLOW + "Enter the directory (or press Enter for current directory): ").strip() or '.'
        
        # Validate Directory
        if not os.path.isdir(args.directory):
            print(Fore.RED + f"Error: '{args.directory}' is not a valid directory.")
            return

        # Report Format Selection
        print(Fore.CYAN + "\nStep 2: Choose Report Format")
        print(Fore.YELLOW + "1. HTML\n2. CSV\n3. Both HTML and CSV")
        format_choice = input(Fore.YELLOW + "Choose a format (1/2/3): ").strip()
        args.format = {"1": "html", "2": "csv", "3": "both"}.get(format_choice, "both")
    
    # Final Directory Validation (in case of missing args)
    if not args.directory or not os.path.isdir(args.directory):
        print(Fore.RED + "Error: You must specify a valid directory to scan.")
        parser.print_help()
        return

    # Category Selection and Pattern Retrieval
    selected_categories = display_category_menu()
    selected_patterns = get_patterns_by_selected_categories(selected_categories)
    print(Fore.GREEN + f"\nSelected Categories: {', '.join(selected_categories)}")

    # Load Previous Hashes for Incremental Scan
    previous_hashes = load_previous_hashes()
    findings = scan_directory(args.directory, previous_hashes, selected_patterns)

    # Display Findings in Console
    print_findings(findings)
    
    # Export Findings in Selected Format(s)
    if args.format in ['csv', 'both']:
        export_to_csv(findings)
    if args.format in ['html', 'both']:
        export_to_html(findings)

if __name__ == "__main__":
    main()
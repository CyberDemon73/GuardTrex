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
import json
from jinja2 import Environment, FileSystemLoader, Template

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

# Load patterns from patterns.json
def load_patterns_from_json(file_path="patterns.json"):
    with open(file_path, 'r') as file:
        return json.load(file)

PATTERNS = load_patterns_from_json()


# Color map for severity levels
COLOR_MAP = {
    'Critical': Fore.MAGENTA + Style.BRIGHT,
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
                if file.endswith(('.java', '.properties', '.xml', '.py', '.js', '.ts', '.rb', '.php', '.go', '.cpp', '.c', '.cs', '.swift', '.kt', '.kts', '.yml', '.yaml', '.json', '.ini', '.env', '.conf', '.config', '.cfg', '.html', '.htm', '.xhtml', '.jsp', '.aspx', '.vue', '.jsx', '.tsx','.jspf', '.tag', '.log', '.txt', '.gradle', '.pom', '.maven', '.jar', '.war', '.ear','.sh', '.bat', '.cmd', '.ps1', '.sql', '.db', '.dbf', '.sqlite', '.bash', '.zsh', '.csh', '.tcsh', '.tf', '.tfvars', '.dockerfile', '.docker-compose.yml', '.md', '.rst', '.csv', '.tsv', '.ipynb','.ascx', '.ashx', '.asmx', '.axd', '.svc', '.cshtml', '.vbhtml', '.master', '.web.config', '.browser', '.edmx', '.mdf', '.licx', '.map', '.xamlx', '.xsd', '.xsl', '.xslt')):

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
    """Export findings to an HTML report with sorting, pagination, search, filter, and collapsible sections."""
    unique_findings = {}
    try:
        # Load template from Template folder
        env = Environment(loader=FileSystemLoader('Template'))
        template = env.get_template('report_template.html')

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

        # Escape potentially harmful characters in findings before rendering
        for finding in findings:
            finding['file'] = html.escape(finding.get('file', 'Unknown file'))
            finding['description'] = html.escape(finding.get('description', 'No description provided'))
            finding['fix_suggestion'] = html.escape(finding.get('fix_suggestion', 'N/A'))
            finding['snippet'] = html.escape(finding.get('snippet', '').strip())

        # Render the template with findings
        rendered_html = template.render(sorted_findings=sorted_findings)

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

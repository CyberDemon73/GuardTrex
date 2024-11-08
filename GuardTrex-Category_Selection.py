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
         'All Actuator Endpoints Exposed', 'High', 'Limit exposure of Actuator endpoints to necessary endpoints only, and secure with authentication.')
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
         'MongoDB Connection String with Credentials', 'High', 'Store MongoDB credentials securely in environment variables.'),
        (re.compile(r'postgresql:\/\/[^\s]+', re.IGNORECASE), 
         'PostgreSQL Connection String', 'High', 'Use environment variables for PostgreSQL connection strings.'),
        (re.compile(r'mysql:\/\/[^\s]+:[^\s]+@', re.IGNORECASE), 
         'MySQL Connection String with Credentials', 'High', 'Avoid storing MySQL credentials directly in the connection string; use secure configurations.'),
        (re.compile(r'mssql:\/\/[^\s]+', re.IGNORECASE), 
         'MSSQL Connection String', 'High', 'Use environment variables for MSSQL connection strings.'),
        (re.compile(r'jdbc:oracle:[^\s]+', re.IGNORECASE), 
         'Oracle JDBC Connection String', 'High', 'Move Oracle connection strings to environment variables.'),
        (re.compile(r'sqlite:\/\/\/?[\w\/\-\.]+\.db', re.IGNORECASE), 
         'SQLite Connection String with File Path', 'Medium', 'Secure SQLite database paths and avoid exposing them in public code.'),
        (re.compile(r'(?i)dynamodb:\/\/(.*?):(.*?)@', re.IGNORECASE), 
         'DynamoDB Connection String with Credentials', 'High', 'Use AWS IAM roles instead of hardcoded credentials for DynamoDB.'),
        (re.compile(r'redis:\/\/:[^\s]+@', re.IGNORECASE), 
         'Redis Connection String with Password', 'High', 'Avoid hardcoding Redis passwords; use secure configurations.'),
        (re.compile(r'elasticsearch:\/\/[^\s]+', re.IGNORECASE), 
         'Elasticsearch Connection String', 'High', 'Move Elasticsearch connection strings to secure configurations.'),
        (re.compile(r'neo4j:\/\/[^\s]+:[^\s]+@', re.IGNORECASE), 
         'Neo4j Connection String with Credentials', 'High', 'Use secure storage for Neo4j credentials.'),
        (re.compile(r'couchdb:\/\/[^\s]+', re.IGNORECASE), 
         'CouchDB Connection String', 'Medium', 'Consider securing CouchDB connection strings in environment variables.'),
        (re.compile(r'influxdb:\/\/[^\s]+', re.IGNORECASE), 
         'InfluxDB Connection String', 'Medium', 'Ensure InfluxDB connection strings are managed securely.'),
        (re.compile(r'cassandra:\/\/[^\s]+', re.IGNORECASE), 
         'Cassandra Connection String', 'High', 'Avoid exposing Cassandra connection strings directly; use secure storage.'),
        (re.compile(r'ftp:\/\/[^\s]+:[^\s]+@', re.IGNORECASE), 
         'FTP Connection with Credentials', 'High', 'Avoid embedding FTP credentials directly in code; use secure storage methods.'),
        (re.compile(r'mongodb\+srv:\/\/[^\s]+', re.IGNORECASE), 
         'MongoDB SRV Connection String', 'High', 'Move MongoDB SRV connection strings to environment variables.'),
        (re.compile(r'amqp:\/\/[^\s]+', re.IGNORECASE), 
         'RabbitMQ Connection String', 'Medium', 'Use secure configurations for RabbitMQ connections.'),
        (re.compile(r'cassandra:\/\/[^\s]+:[^\s]+@', re.IGNORECASE), 
         'Cassandra Connection with Credentials', 'High', 'Avoid hardcoding Cassandra credentials in connection strings.'),
        (re.compile(r'cloudsql:\/\/[^\s]+', re.IGNORECASE), 
         'Google CloudSQL Connection String', 'High', 'Store Google CloudSQL connection strings securely in environment variables.'),
        (re.compile(r'mariadb:\/\/[^\s]+', re.IGNORECASE), 
         'MariaDB Connection String', 'High', 'Avoid exposing MariaDB connection strings directly; use secure configurations.'),
        (re.compile(r'spring\.datasource\.url\s*=\s*".*"', re.IGNORECASE), 
         'Database Connection URL Exposed', 'High', 'Ensure database connection details are stored securely and not exposed in configuration files.'),
        (re.compile(r'spring\.datasource\.username\s*=\s*".*"', re.IGNORECASE), 
         'Database Username Exposed', 'High', 'Store sensitive database credentials securely, outside of source control.'),
        (re.compile(r'spring\.datasource\.password\s*=\s*".*"', re.IGNORECASE), 
         'Database Password Exposed', 'Critical', 'Remove hardcoded database passwords from configuration files; use secure storage.')

    ],
    
    "Cryptography Affairs": [

        (re.compile(r'(?i)(private[_-]?key|public[_-]?key|pem|rsa_key)[\s:=]+[\'"]?.{32,}[\'"]?'), 
         'Hardcoded Cryptographic Key', 'High', 'Store cryptographic keys securely in environment variables or vaults.'),
        (re.compile(r'-----BEGIN RSA PRIVATE KEY-----', re.IGNORECASE), 
         'Hardcoded RSA Private Key', 'High', 'Store RSA private keys in a secure vault rather than embedding them in code.'),
        (re.compile(r'-----BEGIN DSA PRIVATE KEY-----', re.IGNORECASE), 
         'Hardcoded DSA Private Key', 'High', 'Store DSA private keys securely in environment variables or vaults.'),
        (re.compile(r'-----BEGIN EC PRIVATE KEY-----', re.IGNORECASE), 
         'Hardcoded EC Private Key', 'High', 'Avoid hardcoding EC private keys; use a secure key storage solution.'),
        (re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----', re.IGNORECASE), 
         'Hardcoded OpenSSH Private Key', 'High', 'Store OpenSSH keys securely rather than hardcoding them in files or code.'),
        (re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----', re.IGNORECASE), 
         'Hardcoded PGP Private Key', 'High', 'PGP private keys should be stored in a secure location, not in code files.'),
        (re.compile(r'-----BEGIN CERTIFICATE-----', re.IGNORECASE), 
         'Hardcoded PEM Certificate', 'Medium', 'Avoid hardcoding certificates; use secure storage solutions for certificates.'),
        (re.compile(r'(?i)api[_-]?secret[_-]?key\s*[:=]\s*[\'"]?[A-Za-z0-9+/]{32,}[\'"]?', re.IGNORECASE), 
         'Hardcoded API Secret Key', 'High', 'Store API secret keys in environment variables instead of hardcoding them.'),
        (re.compile(r'(?i)aes[_-]?key[\s:=]+[\'"]?[A-Fa-f0-9]{32,}[\'"]?', re.IGNORECASE), 
         'Hardcoded AES Encryption Key', 'High', 'Avoid hardcoding AES keys; store them in a secure vault or environment variable.'),
        (re.compile(r'(?i)des[_-]?key[\s:=]+[\'"]?[A-Fa-f0-9]{16,}[\'"]?', re.IGNORECASE), 
         'Hardcoded DES Encryption Key', 'High', 'Store DES keys securely in environment variables rather than hardcoding.'),
        (re.compile(r'(?i)hmac[_-]?secret[_-]?key[\s:=]+[\'"]?[A-Za-z0-9+/=]{32,}[\'"]?', re.IGNORECASE), 
         'Hardcoded HMAC Secret Key', 'High', 'Store HMAC secret keys in secure storage rather than hardcoding them.'),
        (re.compile(r'(?i)jwt[_-]?secret[\s:=]+[\'"]?[A-Za-z0-9-_]{16,}[\'"]?', re.IGNORECASE), 
         'Hardcoded JWT Signing Secret', 'High', 'Store JWT signing secrets securely in environment variables or vaults.'),
        (re.compile(r'^(ssh-(rsa|dss|ed25519|ecdsa) AAAA[0-9A-Za-z+/]+[=]{0,3})$', re.MULTILINE), 
         'Hardcoded SSH Authorized Key', 'Medium', 'Store SSH authorized keys securely, avoid exposing them in public repositories.'),
        (re.compile(r'-----BEGIN ENCRYPTED PRIVATE KEY-----', re.IGNORECASE), 
         'Hardcoded Encrypted Private Key', 'High', 'Store encrypted private keys securely in a secrets manager.'),
        (re.compile(r'"private_key":\s*"(-----BEGIN PRIVATE KEY-----[^"]+-----END PRIVATE KEY-----)"', re.IGNORECASE), 
         'Hardcoded Google Cloud Private Key', 'High', 'Move Google Cloud private keys to secure storage and reference them via environment variables.'),
        (re.compile(r'(?i)azure[_-]?key[_-]?vault[_-]?key[\s:=]+[\'"]?[A-Za-z0-9-_]{16,}[\'"]?', re.IGNORECASE), 
         'Hardcoded Azure Key Vault Key', 'High', 'Store Azure keys in the Key Vault or secure storage solutions.'),
        (re.compile(r'"private_key":\s*"(-----BEGIN PRIVATE KEY-----[\\nA-Za-z0-9+/=]+-----END PRIVATE KEY-----)"', re.IGNORECASE), 
         'Hardcoded GCP Private Key', 'High', 'Store GCP private keys in secure storage, not in code files.'),
        (re.compile(r'(?i)ibm[_-]?cloud[_-]?api[_-]?key[\s:=]+[\'"]?[A-Za-z0-9-_]{32,}[\'"]?', re.IGNORECASE), 
         'Hardcoded IBM Cloud API Key', 'High', 'Move IBM Cloud API keys to environment variables or secure storage.'),
        (re.compile(r'-----BEGIN RSA PUBLIC KEY-----', re.IGNORECASE), 
         'Hardcoded RSA Public Key', 'Medium', 'Store RSA public keys securely and avoid hardcoding.'),
        (re.compile(r'(ssh-(rsa|dss|ed25519|ecdsa) [A-Za-z0-9+/=]{100,})', re.IGNORECASE), 
         'Hardcoded SSH Public Key', 'Medium', 'Avoid hardcoding SSH public keys; store them securely if necessary.'),
        (re.compile(r'(?i)(symm|symmetrical|encrypt|decrypt)[\s]*key[\s:=]+[\'"]?[A-Fa-f0-9]{32,}[\'"]?', re.IGNORECASE), 
         'Hardcoded Symmetric Encryption Key', 'High', 'Store symmetric keys securely in a secrets manager# Cryptography Affairs'),
        (re.compile(r'(?i)(private[_-]?key|public[_-]?key|pem|rsa_key)[\s:=]+[\'"]?.{32,}[\'"]?'), 
         'Hardcoded Cryptographic Key', 'High', 'Store cryptographic keys securely in environment variables or vaults.'),
        (re.compile(r'-----BEGIN RSA PRIVATE KEY-----', re.IGNORECASE), 
         'Hardcoded RSA Private Key', 'High', 'Store RSA private keys in a secure vault rather than embedding them in code.'),
        (re.compile(r'-----BEGIN DSA PRIVATE KEY-----', re.IGNORECASE), 
         'Hardcoded DSA Private Key', 'High', 'Store DSA private keys securely in environment variables or vaults.'),
        (re.compile(r'-----BEGIN EC PRIVATE KEY-----', re.IGNORECASE), 
         'Hardcoded EC Private Key', 'High', 'Avoid hardcoding EC private keys; use a secure key storage solution.'),
        (re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----', re.IGNORECASE), 
         'Hardcoded OpenSSH Private Key', 'High', 'Store OpenSSH keys securely rather than hardcoding them in files or code.'),
        (re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----', re.IGNORECASE), 
         'Hardcoded PGP Private Key', 'High', 'PGP private keys should be stored in a secure location, not in code files.'),
        (re.compile(r'-----BEGIN CERTIFICATE-----', re.IGNORECASE), 
         'Hardcoded PEM Certificate', 'Medium', 'Avoid hardcoding certificates; use secure storage solutions for certificates.'),
        (re.compile(r'(?i)api[_-]?secret[_-]?key\s*[:=]\s*[\'"]?[A-Za-z0-9+/]{32,}[\'"]?', re.IGNORECASE), 
         'Hardcoded API Secret Key', 'High', 'Store API secret keys in environment variables instead of hardcoding them.'),
        (re.compile(r'(?i)aes[_-]?key[\s:=]+[\'"]?[A-Fa-f0-9]{32,}[\'"]?', re.IGNORECASE), 
         'Hardcoded AES Encryption Key', 'High', 'Avoid hardcoding AES keys; store them in a secure vault or environment variable.'),
        (re.compile(r'(?i)des[_-]?key[\s:=]+[\'"]?[A-Fa-f0-9]{16,}[\'"]?', re.IGNORECASE), 
         'Hardcoded DES Encryption Key', 'High', 'Store DES keys securely in environment variables rather than hardcoding.'),
        (re.compile(r'(?i)hmac[_-]?secret[_-]?key[\s:=]+[\'"]?[A-Za-z0-9+/=]{32,}[\'"]?', re.IGNORECASE), 
         'Hardcoded HMAC Secret Key', 'High', 'Store HMAC secret keys in secure storage rather than hardcoding them.'),
        (re.compile(r'(?i)jwt[_-]?secret[\s:=]+[\'"]?[A-Za-z0-9-_]{16,}[\'"]?', re.IGNORECASE), 
         'Hardcoded JWT Signing Secret', 'High', 'Store JWT signing secrets securely in environment variables or vaults.'),
        (re.compile(r'^(ssh-(rsa|dss|ed25519|ecdsa) AAAA[0-9A-Za-z+/]+[=]{0,3})$', re.MULTILINE), 
         'Hardcoded SSH Authorized Key', 'Medium', 'Store SSH authorized keys securely, avoid exposing them in public repositories.'),
        (re.compile(r'-----BEGIN ENCRYPTED PRIVATE KEY-----', re.IGNORECASE), 
         'Hardcoded Encrypted Private Key', 'High', 'Store encrypted private keys securely in a secrets manager.'),
        (re.compile(r'"private_key":\s*"(-----BEGIN PRIVATE KEY-----[^"]+-----END PRIVATE KEY-----)"', re.IGNORECASE), 
         'Hardcoded Google Cloud Private Key', 'High', 'Move Google Cloud private keys to secure storage and reference them via environment variables.'),
        (re.compile(r'(?i)azure[_-]?key[_-]?vault[_-]?key[\s:=]+[\'"]?[A-Za-z0-9-_]{16,}[\'"]?', re.IGNORECASE), 
         'Hardcoded Azure Key Vault Key', 'High', 'Store Azure keys in the Key Vault or secure storage solutions.'),
        (re.compile(r'"private_key":\s*"(-----BEGIN PRIVATE KEY-----[\\nA-Za-z0-9+/=]+-----END PRIVATE KEY-----)"', re.IGNORECASE), 
         'Hardcoded GCP Private Key', 'High', 'Store GCP private keys in secure storage, not in code files.'),
        (re.compile(r'(?i)ibm[_-]?cloud[_-]?api[_-]?key[\s:=]+[\'"]?[A-Za-z0-9-_]{32,}[\'"]?', re.IGNORECASE), 
         'Hardcoded IBM Cloud API Key', 'High', 'Move IBM Cloud API keys to environment variables or secure storage.'),
        (re.compile(r'-----BEGIN RSA PUBLIC KEY-----', re.IGNORECASE), 
         'Hardcoded RSA Public Key', 'Medium', 'Store RSA public keys securely and avoid hardcoding.'),
        (re.compile(r'(ssh-(rsa|dss|ed25519|ecdsa) [A-Za-z0-9+/=]{100,})', re.IGNORECASE), 
         'Hardcoded SSH Public Key', 'Medium', 'Avoid hardcoding SSH public keys; store them securely if necessary.'),
        (re.compile(r'(?i)(symm|symmetrical|encrypt|decrypt)[\s]*key[\s:=]+[\'"]?[A-Fa-f0-9]{32,}[\'"]?', re.IGNORECASE), 
         'Hardcoded Symmetric Encryption Key', 'High', 'Store symmetric keys securely in a secrets manager')
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
    ],

    "API Endpoints": [
        (re.compile(r'api\.endpoints\.expose\s*=\s*\*', re.IGNORECASE), 
         'All API Endpoints Exposed', 'High', 'Limit exposure of API endpoints to necessary endpoints only, and secure with authentication.'),
        (re.compile(r'api\.endpoints\.expose\s*=\s*(public|internal|private|v1|v2|v3|v4|v5)', re.IGNORECASE), 
         'Exposed API Endpoint (public/internal/private/version)', 'Medium', 'Ensure that exposed endpoints are not disclosing sensitive information.')
    ],

    "Swagger URLs": [
        (re.compile(r'swagger\.ui\.path\s*=\s*/swagger-ui\.html', re.IGNORECASE), 
         'Swagger UI Exposed', 'Medium', 'Restrict access to Swagger UI in production environments.'),
        (re.compile(r'swagger\.api\.docs\.path\s*=\s*/(v1|v2|v3)/api-docs', re.IGNORECASE), 
         'Swagger API Docs Exposed (versioned)', 'Medium', 'Restrict access to Swagger API documentation in production environments.'),
        (re.compile(r'swagger\.api\.docs\.path\s*=\s*/api-docs', re.IGNORECASE), 
         'Swagger API Docs Exposed (generic)', 'Medium', 'Restrict access to Swagger API documentation in production environments.')
    ],

    "Java and Spring Boot Specific Checks": [
        (re.compile(r'PreparedStatement\s+\w+\s*=\s*conn\.prepareStatement\s*\(\s*".*[\+\?].*"\)', re.IGNORECASE),
         'Potential SQL Injection with PreparedStatement Concatenation', 'High', 'Use parameterized queries with placeholders (?) in PreparedStatements to avoid SQL injection vulnerabilities.'),
        (re.compile(r'@NamedQuery\((.*query\s*=\s*".*[\+].*")\)', re.IGNORECASE),
         'Potential SQL Injection in JPA NamedQuery', 'High', 'Avoid concatenating user input in NamedQueries; use parameterized queries.'),
        (re.compile(r'jdbcTemplate\.query(?:For|)\(.*[+].*\)', re.IGNORECASE),
         'Potential SQL Injection with JdbcTemplate', 'High', 'Avoid concatenating user input in JdbcTemplate queries; use placeholders or bind parameters.'),
        (re.compile(r'(Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\s*\(.*[+].*\)', re.IGNORECASE),
         'Potential Command Injection (Runtime/ProcessBuilder)', 'High', 'Avoid passing concatenated strings to Runtime.exec or ProcessBuilder; sanitize inputs and consider safer alternatives.'),
        (re.compile(r'new\s+ObjectInputStream\s*\(\s*.*\)', re.IGNORECASE),
         'Potential Deserialization of Untrusted Data', 'Critical', 'Avoid deserializing untrusted data; use secure alternatives or whitelist classes.'),
        (re.compile(r'new\s+ObjectMapper\(\)\s*\.readValue\s*\(.*\)', re.IGNORECASE),
         'Potential Jackson Deserialization Vulnerability', 'High', 'Ensure Jackson ObjectMapper is configured with safe default typing to avoid deserialization issues.'),
        (re.compile(r'new\s+(SAXParserFactory|DocumentBuilderFactory|SAXBuilder|XMLReader|XMLInputFactory)\(\)', re.IGNORECASE),
         'Potential XXE Vulnerability in XML Parser', 'High', 'Disable external entity processing in XML parsers to prevent XXE attacks.'),
        (re.compile(r'return\s+"redirect:\s*"\s*\+\s*request\.getParameter\(\s*".*"\s*\)', re.IGNORECASE),
         'Potential Open Redirect Vulnerability', 'High', 'Validate and sanitize URL parameters to prevent open redirects.'),
        (re.compile(r'ObjectInputStream\s*\(\s*new\s*FileInputStream\s*\(.*\)\s*\)', re.IGNORECASE), 
         'Insecure Deserialization (ObjectInputStream)', 'High', 'Avoid deserializing untrusted data with ObjectInputStream; use safer alternatives.'),
        (re.compile(r'ObjectInputStream\s*\(\s*request\.getInputStream\s*\(\s*\)\s*\)', re.IGNORECASE), 
         'Insecure Deserialization from User Input', 'High', 'Do not deserialize data directly from user input; validate and sanitize data sources.'),
        (re.compile(r'new\s+ObjectMapper\(\)\.readValue\s*\(.*\)\.typeFactory\.constructType\s*\(.*\)', re.IGNORECASE), 
         'Potential RCE via Jackson Deserialization', 'High', 'Avoid deserializing unknown types in Jackson; use `TypeFactory.defaultInstance()` or `ObjectMapper.enableDefaultTyping` carefully.'),
        (re.compile(r'Registry\s+registry\s*=\s*LocateRegistry\.createRegistry\s*\((1099|default)\)', re.IGNORECASE), 
         'Insecure RMI Registry Exposure', 'High', 'Avoid exposing RMI registry on insecure ports without proper security controls.'),
        (re.compile(r'@Query\s*\(\s*"SELECT\s+.*\s+WHERE\s+.*"\s*\)', re.IGNORECASE), 
         'Potential SQL Injection in Spring Data Repository', 'High', 'Use parameterized queries or criteria queries in Spring Data JPA repositories.'),
        (re.compile(r'entityManager\.createQuery\s*\(\s*".*\s+[+]\s+.*"\s*\)', re.IGNORECASE), 
         'Potential SQL Injection via JPQL (Dynamic Query)', 'High', 'Avoid dynamic JPQL queries with concatenated user input; use parameterized queries.'),
        (re.compile(r'ModelAndView\(\s*".*"\s*,\s*".*"\s*,\s*request\.getParameter\s*\(\s*".*"\s*\)', re.IGNORECASE), 
         'Potential XSS in ModelAndView', 'High', 'Avoid directly rendering user inputs in ModelAndView without sanitization.'),
        (re.compile(r'management\.endpoints\.web\.exposure\.include\s*=\s*\*', re.IGNORECASE), 
         'All Actuator Endpoints Exposed', 'High', 'Limit exposure of Actuator endpoints to necessary ones only and secure them with authentication.'),
        (re.compile(r'management\.endpoints\.web\.exposure\.include\s*=\s*(health|info)', re.IGNORECASE), 
         'Sensitive Actuator Endpoint Exposed', 'Medium', 'Ensure that exposed endpoints are restricted to trusted networks and do not disclose sensitive information.'),
        (re.compile(r'spring\.security\.csrf\.enabled\s*=\s*false', re.IGNORECASE), 
         'CSRF Protection Disabled', 'High', 'Enable CSRF protection for all forms or secure endpoints requiring stateful interactions.'),
        (re.compile(r'Content-Security-Policy\s*:\s*default-src\s+.*;', re.IGNORECASE), 
         'Weak Content Security Policy (CSP)', 'Medium', 'Define a strict CSP to prevent unauthorized resource loading and mitigate XSS risks.'),
        (re.compile(r'new\s+InitialDirContext\(\s*env\s*\)\s*\.\s*search\s*\(.*[+].*\)', re.IGNORECASE), 
         'Potential LDAP Injection (Unfiltered User Input)', 'High', 'Avoid using unfiltered user input in LDAP queries; sanitize inputs properly.'),
        (re.compile(r'new\s+File\s*\(\s*request\.getParameter\s*\(\s*".*"\s*\)\s*\)', re.IGNORECASE), 
         'Potential Path Traversal (User Input in File Paths)', 'High', 'Avoid using raw user inputs in file paths; validate and sanitize path inputs.'),
        (re.compile(r'\$\{\s*request\.(getParameter|getAttribute|getHeader)\(.*\)\s*\}', re.IGNORECASE), 
         'Potential Reflected XSS in Template (Thymeleaf/JSP)', 'High', 'Escape user input before rendering it in Thymeleaf or JSP templates to prevent XSS.'),
        (re.compile(r'@Transactional\s*\(\s*propagation\s*=\s*Propagation\.REQUIRES_NEW\s*\)', re.IGNORECASE),
         'Potential Transaction Management Misconfiguration', 'Medium', 'Avoid using REQUIRES_NEW if not needed; ensure proper transaction boundaries to prevent data integrity issues.'),
        (re.compile(r'getParameter\s*\(\s*".*"\s*\)\s*==\s*null', re.IGNORECASE),
         'Potential Null Parameter Check', 'Low', 'Check for null values securely and avoid potential NPE (Null Pointer Exceptions).'),
        (re.compile(r'spring\.security\.user\.name\s*=\s*.*', re.IGNORECASE),
         'Hardcoded User Credentials', 'High', 'Do not hardcode user credentials; consider using a secure vault for sensitive configurations.'),
        (re.compile(r'spring\.security\.user\.password\s*=\s*.*', re.IGNORECASE),
         'Hardcoded User Password', 'High', 'Do not hardcode passwords; use environment variables or secure storage solutions.'),
        (re.compile(r'@RequestMapping\s*\(.*method\s*=\s*RequestMethod\.GET\s*.*\)', re.IGNORECASE),
         'Potential Sensitive Data Exposure via GET Request', 'High', 'Avoid using GET requests for sensitive operations; prefer POST requests with proper CSRF protection.'),
        (re.compile(r'server\.port\s*=\s*.*', re.IGNORECASE),
         'Insecure Default Server Port', 'Medium', 'Change default server port to a non-standard port to reduce attack surface.'),
        (re.compile(r'server\.error\.include-message\s*=\s*always', re.IGNORECASE),
         'Detailed Error Messages Exposed', 'High', 'Do not expose detailed error messages; configure error handling to show generic messages to users.'),
        (re.compile(r'spring\.security\.oauth2\.client\.registration\..*\.client-secret\s*=\s*.*', re.IGNORECASE),
         'Exposed OAuth2 Client Secret', 'High', 'Do not expose client secrets in application properties; use secure configurations or vaults.'),
        (re.compile(r'if\s*\(\s*request\.getParameter\(\s*".*"\s*\)\s*!=\s*null\s*\)\s*{', re.IGNORECASE),
         'Potential Improper Null Handling', 'Medium', 'Ensure null checks are comprehensive and do not lead to unintended behavior.'),
        (re.compile(r'@PathVariable\s*\(".*"\)\s*.*\s*==\s*null', re.IGNORECASE),
         'Potential Null Check on Path Variable', 'High', 'Validate and sanitize path variables to prevent potential security issues.'),
        (re.compile(r'spring\.security\.remember-me\.key\s*=\s*.*', re.IGNORECASE),
         'Insecure Remember-Me Key', 'High', 'Use a strong, randomly generated key for remember-me functionality.'),
        (re.compile(r'new\s+Gson\(\)\s*\.fromJson\s*\(.*\)', re.IGNORECASE),
         'Potential JSON Deserialization Vulnerability', 'High', 'Avoid deserializing untrusted JSON data; use safe parsing practices.'),
        (re.compile(r'new\s+Socket\s*\(.*[+].*\)', re.IGNORECASE),
         'Potential Socket Injection', 'High', 'Avoid constructing socket connections with concatenated strings; validate inputs properly.'),
        (re.compile(r'@Controller\s*public\s+class\s+.*\s*extends\s+.*Controller\s*{', re.IGNORECASE),
         'Potential Insecure Controller Design', 'Medium', 'Ensure controllers do not expose sensitive operations without proper authentication checks.'),
        (re.compile(r'@PostConstruct\s*public\s*void\s*init\(\)\s*{', re.IGNORECASE),
         'Potential Initialization Vulnerabilities', 'Medium', 'Review initialization methods for security implications, especially if they handle sensitive data.'),
        (re.compile(r'spring\.security\.oauth2\.client\.registration\..*\.client-id\s*=\s*.*', re.IGNORECASE),
         'Exposed OAuth2 Client ID', 'Medium', 'Keep client IDs secure and do not expose them in application properties.'),
        (re.compile(r'spring\.security\.oauth2\.client\.registration\..*\.client-id\s*=\s*.*', re.IGNORECASE),
         'Exposed OAuth2 Client ID', 'Medium', 'Keep client IDs secure and do not expose them in application properties.'),
        (re.compile(r'new\s+HttpURLConnection\s*\(.*[+].*\)', re.IGNORECASE),
         'Potential HTTP Request Injection', 'High', 'Avoid constructing HTTP requests with concatenated strings; sanitize inputs properly.'),
        (re.compile(r'InputStreamReader\s*\(\s*new\s+FileInputStream\s*\(.*\)\s*\)', re.IGNORECASE),
         'Potential Insecure File Input', 'High', 'Avoid reading files without proper validation and sanitization of file paths.'),
        (re.compile(r'spring\.security\.csrf\.enabled\s*=\s*false', re.IGNORECASE),
         'CSRF Protection Disabled', 'High', 'Enable CSRF protection for all forms or secure endpoints requiring stateful interactions.'),
        (re.compile(r'Content-Security-Policy\s*:\s*default-src\s+.*;', re.IGNORECASE),
         'Weak Content Security Policy (CSP)', 'Medium', 'Define a strict CSP to prevent unauthorized resource loading and mitigate XSS risks.'),
        (re.compile(r'new\s+InitialDirContext\(\s*env\s*\)\s*\.\s*search\s*\(.*[+].*\)', re.IGNORECASE),
         'Potential LDAP Injection (Unfiltered User Input)', 'High', 'Avoid using unfiltered user input in LDAP queries; sanitize inputs properly.'),
        (re.compile(r'new\s+File\s*\(\s*request\.getParameter\s*\(\s*".*"\s*\)\s*\)', re.IGNORECASE),
         'Potential Path Traversal (User Input in File Paths)', 'High', 'Avoid using raw user inputs in file paths; validate and sanitize path inputs.'),
        (re.compile(r'\$\{\s*request\.(getParameter|getAttribute|getHeader)\(.*\)\s*\}', re.IGNORECASE),
         'Potential Reflected XSS in Template (Thymeleaf/JSP)', 'High', 'Escape user input before rendering it in Thymeleaf or JSP templates to prevent XSS.'),
        (re.compile(r'new\s+ProcessBuilder\s*\(.*[+].*\)', re.IGNORECASE),
         'Potential Command Injection via ProcessBuilder', 'High', 'Avoid passing concatenated strings to ProcessBuilder; sanitize inputs and consider safer alternatives.'),
        (re.compile(r'spring\.web\.mvc\.view\.prefix\s*=\s*.*', re.IGNORECASE),
         'Potential Path Traversal in View Prefix', 'Medium', 'Avoid dynamic view resolution that includes user input; validate and sanitize view paths.'),
        (re.compile(r'spring\.security\.http\.basic\.enabled\s*=\s*false', re.IGNORECASE),
         'Basic Authentication Disabled', 'High', 'Enable Basic Authentication only if necessary and ensure proper security measures are in place.'),
        (re.compile(r'new\s+URL\s*\(.*[+].*\)', re.IGNORECASE),
         'Potential URL Injection', 'High', 'Avoid constructing URLs with concatenated strings; validate and sanitize URL components.'),
        (re.compile(r'new\s+Cipher\s*\(.*[+].*\)', re.IGNORECASE),
         'Potential Weak Encryption Usage', 'High', 'Avoid using weak or outdated encryption algorithms; use strong, modern cryptographic standards.'),
        (re.compile(r'@Async\s*public\s*void\s*.*\s*\(.*\)', re.IGNORECASE),
         'Potential Race Condition in Async Methods', 'High', 'Ensure thread safety in async methods to prevent race conditions and data inconsistency.'),
        (re.compile(r'final\s+String\s+.*\s*=\s*".*[\+\?].*"', re.IGNORECASE),
         'Potential SQL Injection with String Concatenation', 'High', 'Avoid concatenating strings for SQL queries; use parameterized queries instead.')
    ],

    "Potential Race Condition Indicators Spring Boot": [
        (re.compile(r'@Synchronized', re.IGNORECASE), 
         'Use of @Synchronized Annotation', 'Medium', 'Verify that synchronization meets the application’s concurrency needs.'),
        (re.compile(r'@Lock\(LockModeType\.PESSIMISTIC_WRITE\)', re.IGNORECASE), 
         'Pessimistic Locking Usage', 'Low', 'Check if this locking strategy is appropriately used to prevent race conditions.'),
        (re.compile(r'\bExecutorService\b|\bThreadPoolTaskExecutor\b', re.IGNORECASE), 
         'Custom Thread Pool Usage', 'Medium', 'Ensure proper thread management and safety within custom thread pools.'),
        (re.compile(r'@Async', re.IGNORECASE), 
         'Asynchronous Method Annotation (@Async)', 'High', 'Ensure that @Async methods are thread-safe and do not access shared mutable state.'),
        (re.compile(r'@Transactional\((isolation\s*=\s*Isolation\.(REPEATABLE_READ|SERIALIZABLE))\)', re.IGNORECASE), 
         'High Isolation Level Transactional', 'Low', 'Check if high isolation levels are necessary and properly set to avoid race conditions.'),
        (re.compile(r'new\s+ReentrantLock\(\)', re.IGNORECASE), 
         'Explicit ReentrantLock Usage', 'Medium', 'Review ReentrantLock usage for proper handling of concurrency scenarios.'),
        (re.compile(r'@Transactional', re.IGNORECASE), 
         'Transactional Annotation Usage', 'Medium', 'Ensure transactions are properly scoped to prevent race conditions in concurrent data access.'),
        (re.compile(r'Collections\.synchronized|ConcurrentHashMap|CopyOnWriteArrayList', re.IGNORECASE), 
         'Thread-safe Collection Usage', 'Low', 'Confirm that thread-safe collections are used appropriately to handle concurrent access.')
    ],

    "Insecure Password Encoder": [
        (re.compile(r'new\s+BCryptPasswordEncoder\(\s*0\s*\)', re.IGNORECASE), 
         'Weak BCryptPasswordEncoder Configuration', 'High', 'Use a BCrypt strength of at least 10 for secure password encoding.'),
        (re.compile(r'NoOpPasswordEncoder\.getInstance\(\)', re.IGNORECASE), 
         'NoOpPasswordEncoder (Plaintext Passwords)', 'Critical', 'Do not use NoOpPasswordEncoder; passwords should never be stored in plaintext.')
    ],

    "Log4J Vulnerability Detection": [
        (re.compile(r'log4j[-\.](core|api)[-:](\d+\.\d+\.\d+)', re.IGNORECASE), 
         'Log4J Dependency Found', 'High', 'Check if the Log4J version is vulnerable. Upgrade to a secure version (>=2.17.1 for Log4J 2 or >=1.2.17 for Log4J 1 with mitigations).'),
        (re.compile(r'jndi(?:Lookup)?\s*=\s*["\']?(ldap|ldaps|rmi|dns|iiop|nis|corba|nds):', re.IGNORECASE), 
         'Potentially Vulnerable JNDI Lookup Configuration in Log4J', 'Critical', 'Remove or restrict JNDI lookups in Log4J configuration to mitigate remote code execution risks.'),
        (re.compile(r'log4j2\.formatMsgNoLookups\s*=\s*["\']?false["\']?', re.IGNORECASE),
         'Format Message Lookups Enabled', 'High', 'Set log4j2.formatMsgNoLookups to true to disable message lookups and mitigate CVE-2021-44228.'),
        (re.compile(r'(log4j2?\.properties|log4j2?\.xml)', re.IGNORECASE),
         'Log4J Configuration File Detected', 'Medium', 'Review Log4J configuration file for secure settings and ensure no vulnerable settings are present.'),
        (re.compile(r'log4j\.appender\.[A-Za-z]+\s*=.*SocketAppender', re.IGNORECASE),
         'Insecure Log4J SocketAppender Detected', 'High', 'Use secure communication methods for Log4J appenders to prevent exposure of log data to network interception.'),
        (re.compile(r'log4j[-\.](core|api)[-:]((2\.0|2\.1[0-6]|2\.17\.0)\.\d+)', re.IGNORECASE),
         'Vulnerable Log4J Version Detected', 'Critical', 'Upgrade to Log4J 2.17.1 or later to address known vulnerabilities.'),
        (re.compile(r'\$\{jndi:(ldap|rmi|dns|ldaps):\/\/[^}]+\}', re.IGNORECASE),
         'JNDI Injection Pattern Detected in Logs', 'Critical', 'Sanitize and validate log inputs to prevent JNDI injection attempts.'),
        (re.compile(r'log4j\.appender\.[A-Za-z]+\.RemoteHost\s*=\s*["\']?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}["\']?', re.IGNORECASE),
         'Hardcoded IP in Log4J SocketAppender', 'Medium', 'Avoid hardcoding IP addresses in log appenders. Use secure, dynamic configurations instead.'),
        (re.compile(r'org\.apache\.log4j\.net\.SocketServer', re.IGNORECASE),
         'Log4J SocketServer Detected', 'High', 'Avoid exposing Log4J SocketServer to untrusted networks to prevent unauthorized access to logging services.')
    ],

    "ASP.NET Comprehensive Security Checks": [
        (re.compile(r'<authentication\s+mode\s*=\s*["\']None["\']', re.IGNORECASE),
         'Authentication Mode Set to None', 'High', 'Set authentication mode to Forms, Windows, or another secure method to control access.'),
        (re.compile(r'<compilation\s+debug\s*=\s*["\']true["\']', re.IGNORECASE),
         'Debug Mode Enabled', 'High', 'Disable debug mode in production to prevent exposure of sensitive debugging information.'),
        (re.compile(r'<customErrors\s+mode\s*=\s*["\']Off["\']', re.IGNORECASE),
         'Custom Errors Disabled', 'High', 'Enable custom error handling to avoid exposing stack traces and internal details in production.'),
        (re.compile(r'<machineKey\s+validation\s*=\s*["\']3DES["\']', re.IGNORECASE),
         'Weak Encryption Algorithm (3DES)', 'High', 'Use AES or SHA256 for stronger security in cryptographic operations.'),
        (re.compile(r'<machineKey\s+decryptionKey\s*=\s*["\']AutoGenerate', re.IGNORECASE),
         'Auto-Generated Machine Key', 'High', 'Configure a strong, manually generated machine key to protect session and authentication data.'),
        (re.compile(r'<pages\s+enableViewState\s*=\s*["\']true["\']', re.IGNORECASE),
         'ViewState Enabled', 'Medium', 'Disable ViewState if not needed, especially on pages with sensitive data to reduce attack surface.'),
        (re.compile(r'<pages\s+enableViewStateMac\s*=\s*["\']false["\']', re.IGNORECASE),
         'ViewState MAC Disabled', 'High', 'Enable ViewState MAC to protect ViewState integrity from tampering attacks.'),
        (re.compile(r'<sessionState\s+mode\s*=\s*["\']InProc["\']', re.IGNORECASE),
         'Session State InProc Mode', 'Medium', 'Use StateServer or SQLServer mode for session management in multi-server environments.'),
        (re.compile(r'<sessionState\s+timeout\s*=\s*["\']\d+["\']', re.IGNORECASE),
         'Short Session Timeout', 'Low', 'Set an appropriate session timeout for security without affecting user experience excessively.'),
        (re.compile(r'<httpCookies\s+httpOnlyCookies\s*=\s*["\']false["\']', re.IGNORECASE),
         'HttpOnly Cookies Disabled', 'High', 'Enable HttpOnly cookies to prevent client-side script access to session cookies.'),
        (re.compile(r'<httpCookies\s+requireSSL\s*=\s*["\']false["\']', re.IGNORECASE),
         'Secure Cookies Disabled', 'High', 'Enable secure cookies to prevent them from being transmitted over unencrypted connections.'),
        (re.compile(r'<sessionState\s+cookieSameSite\s*=\s*["\']None["\']', re.IGNORECASE),
         'SameSite Cookie Set to None', 'Medium', 'Set SameSite=Lax or SameSite=Strict to protect cookies from CSRF attacks.'),
        (re.compile(r'<httpProtocol>\s*<customHeaders>\s*<add\s+name\s*=\s*["\']X-XSS-Protection["\']\s+value\s*=\s*["\']0["\']', re.IGNORECASE),
         'X-XSS-Protection Disabled', 'High', 'Enable X-XSS-Protection to help protect against reflected XSS attacks.'),
        (re.compile(r'<httpProtocol>\s*<customHeaders>(?!.*X-Content-Type-Options)', re.IGNORECASE),
         'Missing X-Content-Type-Options Header', 'Medium', 'Add the X-Content-Type-Options header to protect against MIME-type sniffing attacks.'),
        (re.compile(r'<httpProtocol>\s*<customHeaders>(?!.*Strict-Transport-Security)', re.IGNORECASE),
         'Missing Strict-Transport-Security Header', 'High', 'Use the Strict-Transport-Security header to enforce HTTPS and protect against downgrade attacks.'),
        (re.compile(r'<add\s+key\s*=\s*["\'](.*password|.*connectionString)["\']\s+value\s*=\s*["\'].*["\']', re.IGNORECASE),
         'Sensitive Data in Web.Config', 'High', 'Avoid storing sensitive data directly in Web.config. Use encryption or secure environment variables.'),
        (re.compile(r'<add\s+name\s*=\s*["\']Access-Control-Allow-Origin["\']\s+value\s*=\s*["\']\*["\']', re.IGNORECASE),
         'CORS Policy Allows All Origins', 'High', 'Limit CORS to specific trusted domains to prevent unauthorized data access.'),
        (re.compile(r'<httpHandlers>\s*<add\s+verb\s*=\s*["\']\*["\']\s+path\s*=\s*["\'].*\.(asmx|svc)["\']', re.IGNORECASE),
         'ASP.NET Web Service Endpoints Exposed', 'High', 'Restrict access to web service endpoints and secure them with authentication.'),
        (re.compile(r'<pages\s+enableEventValidation\s*=\s*["\']false["\']', re.IGNORECASE),
         'Event Validation Disabled', 'High', 'Enable event validation to prevent unauthorized postback and request forgery attacks.'),
        (re.compile(r'<system.web>\s*<pages\s+enableViewStateMac\s*=\s*["\']false["\']', re.IGNORECASE),
         'ViewState MAC Disabled', 'High', 'Enable ViewState MAC to prevent unauthorized view state tampering.'),
        (re.compile(r'<httpErrors\s+errorMode\s*=\s*["\']Detailed["\']', re.IGNORECASE),
         'Detailed Error Mode Enabled', 'High', 'Disable detailed error mode in production to prevent sensitive data exposure in error messages.'),
        (re.compile(r'<add\s+name\s*=\s*["\']X-Powered-By["\']', re.IGNORECASE),
         'X-Powered-By Header Present', 'Low', 'Remove the X-Powered-By header to avoid revealing technology stack information to potential attackers.'),
        (re.compile(r'<httpProtocol>\s*<customHeaders>(?!.*Content-Security-Policy)', re.IGNORECASE),
         'Missing Content-Security-Policy Header', 'High', 'Define a Content-Security-Policy header to control resources loaded and reduce the risk of XSS.'),
        (re.compile(r'<security>\s*<access\s+sslFlags\s*=\s*["\']None["\']', re.IGNORECASE),
         'SSL Disabled for Directory', 'High', 'Set sslFlags to "Ssl" or "SslNegotiateCert" to enforce HTTPS for directory access.'),
        (re.compile(r'<cryptoSettings>\s*<cryptography defaultKeyContainerName\s*=\s*["\']SystemWebCrypto["\']', re.IGNORECASE),
         'Insecure Default Cryptography Settings', 'Medium', 'Use custom cryptographic settings and keys for better security.'),
        (re.compile(r'<add\s+key\s*=\s*["\'](api[_-]?key|secret[_-]?key)["\']\s+value\s*=\s*["\'].*["\']', re.IGNORECASE),
         'Hardcoded API Secret Key', 'High', 'Avoid hardcoding API keys and secrets in configuration files; use secure storage solutions.'),
        (re.compile(r'(SqlCommand|ExecuteNonQuery|ExecuteReader|ExecuteScalar|DataAdapter)\s*\(.*["\'].*\s*[+].*\)', re.IGNORECASE),
         'Potential SQL Injection', 'High', 'Use parameterized queries to prevent SQL injection vulnerabilities.'),
        (re.compile(r'XmlDocument\s*\(\)\.Load\s*\(.*\)', re.IGNORECASE),
         'Potential XXE Vulnerability', 'High', 'Disable DTD processing in XML parsers to prevent XXE attacks.'),
        (re.compile(r'<requestLimits\s+maxAllowedContentLength\s*=\s*["\']\d{1,8}["\']', re.IGNORECASE),
         'Insecure File Upload Size Limit', 'Medium', 'Set an appropriate file upload size limit to prevent denial of service attacks.'),
        (re.compile(r'<httpRuntime\s+requestValidationMode\s*=\s*["\']2.0["\']', re.IGNORECASE),
         'Legacy Request Validation Mode', 'High', 'Upgrade request validation to mode 4.0 or higher to improve input validation and security.'),
        (re.compile(r'BinaryFormatter\s*=\s*new\s+BinaryFormatter\(\)', re.IGNORECASE),
         'Potential Insecure Deserialization', 'Critical', 'Avoid using BinaryFormatter with untrusted data as it may lead to remote code execution.'),
        (re.compile(r'JwtBearerOptions\s*\(\s*TokenValidationParameters\s*=\s*\{.*ValidateAudience\s*=\s*false', re.IGNORECASE),
         'JWT Token Validation Disabled', 'High', 'Enable JWT audience validation to ensure tokens are only valid for intended applications.'),
        (re.compile(r'<membership\s+defaultProvider\s*=\s*["\']AspNetSqlMembershipProvider["\']', re.IGNORECASE),
         'Weak Authentication Provider (SQL Membership)', 'High', 'Consider using a stronger authentication provider like Identity Framework.'),
        (re.compile(r'<sessionState\s+regenerateExpiredSessionId\s*=\s*["\']false["\']', re.IGNORECASE),
         'Session Fixation Vulnerability', 'High', 'Enable regenerateExpiredSessionId to mitigate session fixation attacks.')
    ]

}


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
                if file.endswith(('.java', '.properties', '.xml', '.py', '.js', '.ts', '.rb', '.php', '.go', '.cpp', '.c', '.cs', '.swift', '.kt', '.kts', '.yml', '.yaml', '.json', '.ini', '.env', '.conf', '.config', '.cfg', '.html', '.htm', '.xhtml', '.jsp', '.aspx', '.vue', '.jsx', '.tsx', '.jspf', '.tag', '.log', '.txt', '.gradle', '.pom', '.maven', '.jar', '.war', '.ear', '.sh', '.bat', '.cmd', '.ps1', '.sql', '.db', '.dbf', '.sqlite', '.bash', '.zsh', '.csh', '.tcsh', '.tf', '.tfvars', '.dockerfile', '.docker-compose.yml', '.md', '.rst', '.csv', '.tsv', '.ipynb')):
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
                .critical { background-color: #f5c6cb; color: #721c24; }  /* Style for critical severity */
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
                <span class="summary-item critical"><span class="icon">🔴</span>Critical: {{ sorted_findings['Critical'] | length }}</span>
                <span class="summary-item high"><span class="icon">🔴</span>High: {{ sorted_findings['High'] | length }}</span>
                <span class="summary-item medium"><span class="icon">🟠</span>Medium: {{ sorted_findings['Medium'] | length }}</span>
                <span class="summary-item low"><span class="icon">🟢</span>Low: {{ sorted_findings['Low'] | length }}</span>
                <span class="summary-item informational"><span class="icon">🔵</span>Informational: {{ sorted_findings['Informational'] | length }}</span>
            </div>

            <div class="controls">
                <input type="text" id="search" class="search-box" placeholder="Search by file, description, or fix..." aria-label="Search findings">
                <select id="severity-filter" class="filter" aria-label="Filter by severity">
                    <option value="all">All Severities</option>
                    <option value="Critical">Critical</option>
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
                {% for severity in ['Critical', 'High', 'Medium', 'Low', 'Informational'] %}
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

import os
import re
import logging
import hashlib
import csv
import yaml
import xml.etree.ElementTree as ET
from colorama import Fore, Style, init
from lxml import etree
import html
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

    # Actuator Endpoints
    (re.compile(r'management\.endpoints\.web\.exposure\.include\s*=\s*\*', re.IGNORECASE), 
     'All Actuator Endpoints Exposed', 'High', 'Limit exposure of Actuator endpoints to necessary endpoints only, and secure with authentication.'),
    (re.compile(r'management\.endpoints\.web\.exposure\.include\s*=\s*(health|info)', re.IGNORECASE), 
     'Exposed Actuator Endpoint (health/info)', 'Medium', 'Ensure that exposed endpoints are not disclosing sensitive information.'),

    # CSRF Protection
    (re.compile(r'spring\.security\.csrf\.enabled\s*=\s*false', re.IGNORECASE), 
     'CSRF Protection Disabled', 'High', 'Enable CSRF protection for all forms or secure endpoints requiring stateful interactions.'),

    # Password Storage
    (re.compile(r'spring\.data\.source\.password\s*=\s*[\'"]?[a-zA-Z0-9]*[\'"]?', re.IGNORECASE), 
     'Insecure Password Storage', 'High', 'Store database credentials in a secure configuration provider or environment variable.'),
    

    # HTTPS Enforcement
    (re.compile(r'http\.server\.secure-port\s*=\s*8080', re.IGNORECASE), 
     'HTTP Connection Allowed', 'High', 'Ensure all connections enforce HTTPS with SSL/TLS configurations.'),
    (re.compile(r'server\.ssl\.enabled\s*=\s*false', re.IGNORECASE), 
     'SSL/TLS Disabled', 'High', 'Enable SSL/TLS to ensure secure communication over HTTPS.'),


    # Response Headers Security
    (re.compile(r'Content-Security-Policy\s*:\s*default-src\s+.*;', re.IGNORECASE), 
     'Missing or Weak Content Security Policy (CSP)', 'Medium', 'Define a strict CSP to prevent unauthorized resource loading and mitigate XSS risks.'),
    (re.compile(r'spring\.web\.cors\.allowed-origin-patterns\s*=\s*\*', re.IGNORECASE), 
     'CORS Policy Allows All Origins', 'High', 'Restrict CORS to only trusted domains. Avoid using wildcard (*) in production.'),
    (re.compile(r'X-Frame-Options\s*:\s*ALLOW', re.IGNORECASE), 
     'X-Frame-Options Header Allows Embedding', 'Medium', 'Set X-Frame-Options header to DENY or SAMEORIGIN to prevent clickjacking.'),


    # H2 Console
    (re.compile(r'spring\.h2\.console\.enabled\s*=\s*true', re.IGNORECASE), 
     'Insecure H2 Console Exposure', 'High', 'Disable H2 console in production or secure with authentication.'),

    # Debugging Enablement Check
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
     'Debug Mode Enabled in Laravel', 'High', 'Disable APP_DEBUG in production to prevent detailed error messages.'),
    (re.compile(r'process\.env\.NODE_ENV\s*=\s*[\'"]development[\'"]', re.IGNORECASE), 
     'Vue.js Development Mode Enabled', 'High', 'Ensure NODE_ENV is set to "production" for production deployments.'),
    (re.compile(r'process\.env\.NODE_ENV\s*=\s*[\'"]development[\'"]', re.IGNORECASE), 
     'React Development Mode Enabled', 'High', 'Set NODE_ENV to "production" in React to optimize performance and prevent debug information leakage.'),
    (re.compile(r'environment\.production\s*=\s*false', re.IGNORECASE), 
     'Angular Development Mode', 'High', 'Set environment.production to true in Angular for production builds to disable debugging.'),
    (re.compile(r'config\.log_level\s*=\s*:debug', re.IGNORECASE), 
     'Rails Log Level Set to Debug', 'Medium', 'Set log level to :info or :warn in production to avoid excessive logging of sensitive information.'),
    (re.compile(r'app\.set\(\s*[\'"]env[\'"]\s*,\s*[\'"]development[\'"]\s*\)', re.IGNORECASE), 
     'Express Development Mode', 'High', 'Set environment to "production" in Express to prevent debug information exposure.'),
    (re.compile(r'logger\.level\s*=\s*DEBUG', re.IGNORECASE), 
     'Elasticsearch Debug Logging Enabled', 'High', 'Set Elasticsearch logger level to WARN or ERROR in production to avoid excessive logging.'),
    (re.compile(r'general_log\s*=\s*ON', re.IGNORECASE), 
     'MySQL General Query Log Enabled', 'High', 'Disable general query log in MySQL production environments to avoid logging sensitive data.'),
    (re.compile(r'profile\s*:\s*1', re.IGNORECASE), 
     'MongoDB Profiling Enabled', 'Medium', 'Set profiling level to 0 in MongoDB production environments to avoid excessive logging.'),
    (re.compile(r'\bNODE_ENV\s*=\s*development\b', re.IGNORECASE), 
     'Docker Development Mode', 'High', 'Set NODE_ENV to "production" in Docker containers to prevent debug mode.'),
    (re.compile(r'mode\s*:\s*[\'"]development[\'"]', re.IGNORECASE), 
     'Webpack Development Mode Enabled', 'High', 'Set Webpack mode to "production" for optimized production builds.'),
    (re.compile(r'LogLevel\s+debug', re.IGNORECASE), 
     'Apache Debug Log Level Enabled', 'Medium', 'Set LogLevel to warn or error in production to avoid excessive logging.'),



    # API Keys and Secrets
    (re.compile(r'(?i)(api[_-]?secret|secret[_-]?token)[\s:=]+[\'"]?.{16,}[\'"]?'), 
     'Hardcoded API Secret Token', 'High', 'Store API secret tokens in secure environment variables.'),
    (re.compile(r'(?i)client[_-]?secret[\s:=]+[\'"]?.{16,}[\'"]?'), 
     'Hardcoded OAuth Client Secret', 'High', 'Store OAuth client secrets securely in environment variables.'),
    (re.compile(r'(?i)(encryption[_-]?key|aes[_-]?key)[\s:=]+[\'"]?.{16,}[\'"]?'), 
     'Hardcoded Encryption Key', 'High', 'Avoid hardcoding encryption keys; use secure key management solutions.'),
    (re.compile(r'(?i)jwt[_-]?secret[\s:=]+[\'"]?.{16,}[\'"]?'), 
     'Hardcoded JWT Secret Key', 'High', 'Store JWT secrets in secure storage rather than directly in code.'),
    (re.compile(r'(?i)ssh[_-]?private[_-]?key[\s:=]+[\'"]?.{16,}[\'"]?'), 
     'Hardcoded SSH Private Key', 'High', 'Move SSH private keys to a secure vault instead of hardcoding.'),
    (re.compile(r'(?i)sftp[_-]?password[\s:=]+[\'"]?.{6,}[\'"]?'), 
     'Hardcoded SFTP Password', 'High', 'Store SFTP passwords securely in environment variables.'),
    (re.compile(r'(?i)ldap[_-]?password[\s:=]+[\'"]?.{6,}[\'"]?'), 
     'Hardcoded LDAP Password', 'High', 'Store LDAP passwords securely in a secrets manager.'),
    (re.compile(r'(?i)smtp[_-]?password[\s:=]+[\'"]?.{6,}[\'"]?'), 
     'Hardcoded SMTP Password', 'High', 'Store SMTP passwords in secure configuration providers.'),
    (re.compile(r'(?i)proxy[_-]?password[\s:=]+[\'"]?.{6,}[\'"]?'), 
     'Hardcoded Proxy Password', 'High', 'Secure proxy passwords using environment variables or a secrets manager.'),
    (re.compile(r'(?i)(wifi|wpa|wep)[_\-]?(password|key)[\s:=]+[\'"]?.{8,}[\'"]?'), 
     'Hardcoded WiFi Password', 'Medium', 'Store WiFi credentials securely; avoid hardcoding.'),
    (re.compile(r'(?i)(secret[_-]?access[_-]?key)[\s:=]+[\'"]?.{16,}[\'"]?'), 
     'Hardcoded Secret Access Key', 'High', 'Store access keys securely, using environment variables or secure storage.'),
    (re.compile(r'(?i)(basic[_-]?auth|authorization)[\s:=]+[\'"]?Basic\s+[A-Za-z0-9+/=]{16,}[\'"]?'), 
     'Hardcoded Basic Auth Credentials', 'High', 'Avoid hardcoding basic auth credentials; use environment variables.'),
    (re.compile(r'(?i)root[_-]?password[\s:=]+[\'"]?.{6,}[\'"]?'), 
     'Hardcoded Root Password', 'High', 'Store root passwords securely in environment variables.'),
    (re.compile(r'(?i)(web[_-]?service|ws)[_\-]?token[\s:=]+[\'"]?.{16,}[\'"]?'), 
     'Hardcoded Web Service Token', 'High', 'Store web service tokens in environment variables or secure storage.'),
    (re.compile(r'(?i)auth[_-]?key[\s:=]+[\'"]?.{16,}[\'"]?'), 
     'Hardcoded Authentication Key', 'High', 'Avoid hardcoding authentication keys; use secure storage solutions.'),
    (re.compile(r'(?i)session[_-]?key[\s:=]+[\'"]?.{16,}[\'"]?'), 
     'Hardcoded Session Key', 'High', 'Store session keys securely, using environment variables or secure storage solutions.'),
    (re.compile(r'(?i)admin[_-]?password[\s:=]+[\'"]?.{6,}[\'"]?'), 
     'Hardcoded Admin Password', 'High', 'Store admin passwords securely in environment variables.'),
    (re.compile(r'(?i)external[_-]?api[_-]?password[\s:=]+[\'"]?.{6,}[\'"]?'), 
     'Hardcoded External API Password', 'High', 'Secure API passwords using environment variables or secrets manager.'),
    (re.compile(r'(?i)internal[_-]?service[_-]?password[\s:=]+[\'"]?.{6,}[\'"]?'), 
     'Hardcoded Internal Service Password', 'High', 'Store service passwords securely, not directly in code.'),
    (re.compile(r'(?i)vpn[_-]?password[\s:=]+[\'"]?.{6,}[\'"]?'), 
     'Hardcoded VPN Password', 'High', 'Avoid hardcoding VPN passwords; use secure storage solutions.'),
    (re.compile(r'(?i)github[_-]?token[\s:=]+[\'"]?.{16,}[\'"]?'), 
     'Hardcoded GitHub Token', 'High', 'Store GitHub tokens securely in environment variables.'),
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
     (re.compile(r'(?i)(password|passwd|pwd|secret|auth|key|token)[\s:=]+[\'"](?!(request\.form\.get|os\.getenv|config\.get|secrets\.get|request\.args\.get|request\.json)).{6,}[\'"]'), 
     'Hardcoded Password', 'High', 'Store passwords securely using environment variables or secrets manager.'),


    # Database Connection Strings
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


    # Cryptography Affairs
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
     'Hardcoded Symmetric Encryption Key', 'High', 'Store symmetric keys securely in a secrets manager or environment variable.'),


    # Personally Identifiable Information (PII)
    (re.compile(r'\b\d{1,2}[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])\d{7}\b'), 
     'Potential Egyptian National ID Number', 'High', 'Ensure that Egyptian National IDs are securely stored and masked when displayed.'),
    (re.compile(r'\b[A-Z]{1}[0-9]{8}\b'), 
     'Potential Egyptian Passport Number', 'High', 'Avoid storing passport numbers directly; secure them if necessary.'),
    (re.compile(r'\b(?:\+?20)?(1[0-2,5]{1}[0-9]{8})\b'), 
     'Potential Egyptian Phone Number', 'Medium', 'Avoid hardcoding phone numbers; store them securely and use masking where possible.'),
    #(re.compile(r'\b[1-9][0-9]{4}\b'), 
     #'Potential Egyptian Postal Code', 'Low', 'Verify that postal codes are stored securely if used for identification purposes.'),
    (re.compile(r'\b[0-9]{16}\b'), 
     'Potential Egyptian Bank Account Number', 'High', 'Store bank account numbers securely and avoid exposing them directly.'),
    (re.compile(r'\b[أ-ي]{1,2}\s?\d{1,4}\s?[أ-ي]{0,2}\b', re.IGNORECASE), 
     'Potential Egyptian License Plate Number', 'Medium', 'License plate numbers should be stored securely if needed for identification.'),
    (re.compile(r'\b[0-9]{14}\b'), 
     'Potential Egyptian Driving License Number', 'Medium', 'Store driving license numbers securely and avoid hardcoding.'),
    (re.compile(r'\b[0-9]{12}\b'), 
     'Potential Egyptian Birth Certificate Number', 'High', 'Ensure birth certificate numbers are stored securely and used minimally.'),
    (re.compile(r'\b[0-9]{9}\b'), 
     'Potential Egyptian Tax Identification Number', 'High', 'Tax IDs should be stored securely and masked if displayed publicly.'),
    #(re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b'), 
     #'Potential Credit Card Number (Egypt)', 'High', 'Store credit card information securely using a PCI-compliant payment gateway.'),
    (re.compile(r'\b\d{2}[A-Za-z]{2}\d{6}\b'), 
     'Potential Egyptian Health Insurance Number', 'High', 'Store health insurance numbers securely and limit their exposure.'),
    #(re.compile(r'\b[0-9]{2}-[0-9]{6}\b'), 
     #'Potential Egyptian University ID Number', 'Medium', 'Store student IDs securely, especially if used for identification purposes.'),
    (re.compile(r'\b(?:2[0-9]{9})\b'),  # Egyptian Mobile Payment ID (e.g., Fawry, Vodafone Cash)
     'Potential Egyptian Mobile Payment ID', 'High', 'Mobile payment IDs should be stored securely, avoiding direct exposure.'),


    # Credit Card Numbers
    (re.compile(r'\b5[1-5][0-9]{14}\b'), 
     'Potential Credit Card Number (MasterCard)', 'High', 'Do not store credit card numbers directly; use a secure payment gateway.'),
    (re.compile(r'\b3[47][0-9]{13}\b'), 
     'Potential Credit Card Number (American Express)', 'High', 'Do not store credit card numbers directly; use a secure payment gateway.'),
    (re.compile(r'\b6(?:011|5[0-9]{2})[0-9]{12}\b'), 
     'Potential Credit Card Number (Discover)', 'High', 'Do not store credit card numbers directly; use a secure payment gateway.'),
    (re.compile(r'\b3(?:0[0-5]|[68][0-9])[0-9]{11}\b'), 
     'Potential Credit Card Number (Diners Club)', 'High', 'Do not store credit card numbers directly; use a secure payment gateway.'),
    (re.compile(r'\b(?:2131|1800|35[0-9]{3})[0-9]{11}\b'), 
     'Potential Credit Card Number (JCB)', 'High', 'Do not store credit card numbers directly; use a secure payment gateway.'),
    (re.compile(r'\b62[0-9]{14,17}\b'), 
     'Potential Credit Card Number (UnionPay)', 'High', 'Do not store credit card numbers directly; use a secure payment gateway.'),
    (re.compile(r'\b(?:5018|5020|5038|6304|6759|6761|6763|0604|6390)[0-9]{8,15}\b'), 
     'Potential Credit Card Number (Maestro)', 'High', 'Do not store credit card numbers directly; use a secure payment gateway.'),
    (re.compile(r'\b4(?:026|17500|405|508|844|91[37])[0-9]{10}\b'), 
     'Potential Credit Card Number (Visa Electron)', 'High', 'Do not store credit card numbers directly; use a secure payment gateway.'),


    # Multiple Injection Patterns
    (re.compile(r'(?i)(os\.system|subprocess\.popen|subprocess\.call|subprocess\.run|eval|exec|popen|shell_exec|system|passthru|ProcessBuilder)', re.IGNORECASE), 
     'Potential Command Injection (Dangerous Function Usage)', 'High', 'Avoid using potentially dangerous functions that can lead to command injection.'),
    (re.compile(r'(os\.system|subprocess\.(popen|call|run))\s*\(.*[+].*\)', re.IGNORECASE), 
     'Potential Command Injection (Shell Command Concatenation)', 'High', 'Avoid concatenating user input directly into shell commands. Use parameterized inputs instead.'),
    (re.compile(r'(shell_exec|exec|passthru|system)\s*\(\s*["\'].*?\$_(GET|POST|REQUEST|SERVER).*?["\']\s*\)', re.IGNORECASE), 
     'Potential Command Injection in PHP (User Input Concatenation)', 'High', 'Avoid using user input directly in shell commands; sanitize or escape inputs.'),
    (re.compile(r'`.*\$\(.*\).*`', re.IGNORECASE), 
     'Potential Command Injection (Bash Backticks)', 'High', 'Avoid using backticks with untrusted input in shell commands; use safer alternatives.'),
    # SQL Injection Detection ----------------#
    (re.compile(r'(execute|query|prepare|executeQuery|executeUpdate)\s*\(.*[+].*\)', re.IGNORECASE), 
     'Potential SQL Injection (Concatenated SQL Commands)', 'High', 'Avoid concatenating user inputs in SQL commands; use parameterized queries.'),
    (re.compile(r'(select|insert|update|delete|drop|exec|alter)\s+.*\s+where\s+.*[+]', re.IGNORECASE), 
     'Potential SQL Injection (Dynamic SQL Query)', 'High', 'Avoid dynamically constructing SQL queries with user input; use parameterized queries instead.'),
    (re.compile(r'execute\(\s*f?["\'].*?\{\}.*?["\']\s*\)', re.IGNORECASE), 
     'Potential SQL Injection in Python (f-strings or .format)', 'High', 'Avoid using f-strings or .format with SQL statements; use parameterized queries.'),
    (re.compile(r'["\']\s*\+\s*(\w+)\s*\+\s*["\']', re.IGNORECASE), 
     'Potential SQL Injection (String Concatenation)', 'High', 'Avoid concatenating user input in SQL queries. Use parameterized queries or prepared statements instead.'),
    (re.compile(r'(executeQuery|executeUpdate|prepareStatement)\s*\(\s*".*\+.*\+\s*".*\)', re.IGNORECASE), 
     'Potential SQL Injection (User Input in SQL Statements)', 'High', 'Avoid directly using user inputs in SQL statements; use placeholders with parameterized queries instead.'),
    (re.compile(r'(?i)\b(SELECT|INSERT|DELETE|UPDATE|DROP|EXEC)\b\s*.*\b(WHERE|AND|OR)\b\s*.*\b(=|LIKE)\b\s*.*\+', re.IGNORECASE), 
     'Potential SQL Injection (SQL Keywords in Query)', 'High', 'Use parameterized queries or ORMs to prevent SQL injection risks.'),
    (re.compile(r'(?i)(xp_cmdshell|exec|execute|sp_executesql|sp_addextendedproc|sysobjects|syscolumns)', re.IGNORECASE), 
     'Potential SQL Injection (Suspicious SQL Functions)', 'High', 'Avoid using these SQL functions with untrusted input as they can lead to SQL injection vulnerabilities.'),
    (re.compile(r'(--|;|\bAND\b|\bOR\b|\bNOT\b).*\b(SELECT|UPDATE|DELETE|INSERT|EXEC)\b', re.IGNORECASE), 
     'Potential SQL Injection (Inline SQL Injection Patterns)', 'High', 'Ensure all SQL inputs are sanitized and parameterized to prevent injection.'),
    (re.compile(r'(["\']).*\1\s*;\s*["\']', re.IGNORECASE), 
     'Unescaped Quotes in SQL Statements', 'Medium', 'Use proper escaping or parameterized queries to avoid SQL injection vulnerabilities.'),
    #-----------------------------------------#
    # Cross-Site Scripting -------------------#
    (re.compile(r'<script\b[^>]*>(.*?)<\/script>', re.IGNORECASE), 
     'Potential XSS (Inline JavaScript)', 'High', 'Avoid directly including user input in inline JavaScript; use proper encoding or sanitization.'),
    (re.compile(r'<.*?\bon\w+\s*=\s*["\'].*?\+.*?["\'].*?>', re.IGNORECASE), 
     'Potential XSS (Event Handler in HTML Tag)', 'High', 'Avoid using untrusted data in HTML event handlers. Sanitize and encode data before insertion.'),
    (re.compile(r'document\.(cookie|write|location)|window\.(location|name|open)', re.IGNORECASE), 
     'Potential XSS (Inline JavaScript Accessing Document/Window)', 'High', 'Avoid using untrusted data with document and window properties without sanitization.'),
    (re.compile(r'<.*?style\s*=\s*["\'].*?expression\(', re.IGNORECASE), 
     'Potential XSS (CSS Expression)', 'High', 'Avoid using CSS expressions with user data as it can lead to XSS vulnerabilities.'),
    (re.compile(r'<a\b[^>]*\bhref\s*=\s*[\'"]\s*javascript:', re.IGNORECASE), 
     'Potential XSS (JavaScript URI in Link)', 'High', 'Avoid using JavaScript URIs in link href attributes with untrusted data.'),
    (re.compile(r'(<\w+\s+[^>]*\b(?:src|href|data)\s*=\s*[\'"]?javascript:.*[\'"]?)', re.IGNORECASE), 
     'Potential Reflected XSS (Untrusted Data in HTML Attributes)', 'High', 'Use proper input validation, escaping, and CSP headers to prevent XSS.'),
    (re.compile(r'<(iframe|embed|object|applet|form|base|link|meta)[^>]*>', re.IGNORECASE), 
     'Potential XSS (Dangerous HTML Tags)', 'Medium', 'Avoid using potentially dangerous HTML tags with untrusted data. Sanitize inputs and use CSP.'),
    (re.compile(r'{{\s*[^}]+?\s*}}', re.IGNORECASE), 
     'Potential XSS (Lack of HTML Escaping)', 'High', 'Use proper encoding for all user-supplied data in templates to prevent XSS vulnerabilities.'),
    (re.compile(r':\s*["\']?(\w+)\s*\+\s*["\']?(\w+)\s*\+', re.IGNORECASE), 
     'Potential XSS (Unescaped User Input in JSON)', 'High', 'Ensure user inputs are properly encoded before inserting them into JSON responses.'),
    (re.compile(r'location\.search|document\.location|window\.location|URL\.query', re.IGNORECASE), 
     'Potential Reflected XSS (Untrusted URL Parameters)', 'High', 'Sanitize and encode URL parameters before using them in client-side code.'),
    (re.compile(r'<.*?\s(?:src|href|data)\s*=\s*["\']?\s*(javascript|data):', re.IGNORECASE), 
     'Potential XSS (JavaScript/Data URI)', 'High', 'Avoid using user input in HTML attributes like src and href without sanitization.'),
    #------------------------------------------------#
    (re.compile(r'<!ENTITY\s+\w+\s+SYSTEM\s+[\'"]http://', re.IGNORECASE), 
     'Potential XML External Entity Injection (XXE)', 'High', 'Disable external entity processing when parsing XML data.'),
    (re.compile(r'(\(|\)|&|\||=|\*).*(request\.getParameter|request\.getQueryString|request\.getInputStream)', re.IGNORECASE), 
     'Potential LDAP Injection', 'High', 'Avoid using unfiltered user input in LDAP queries; use LDAP-safe encoding or parameterized filters.'),
    (re.compile(r'\$\{.*?request\.(body|query|params)\}', re.IGNORECASE), 
     'Potential JavaScript Template Injection', 'High', 'Avoid inserting unescaped user input in JavaScript template literals.'),
    (re.compile(r'\{\{\s*request\.(args|get|form|json)\s*\}\}', re.IGNORECASE), 
     'Potential Server-Side Template Injection (Python)', 'High', 'Avoid direct inclusion of user input in templates; sanitize or escape inputs.'),
    (re.compile(r'(eval|exec)\s*\(.*\+.*\)', re.IGNORECASE), 
     'Potential Code Injection (eval/exec with Concatenation)', 'High', 'Avoid using eval or exec with user inputs; sanitize inputs and use safer alternatives.'),
    (re.compile(r'(response\.setHeader|header\()?\s*[\'"](Location|Content-Disposition|Set-Cookie)[\'"]\s*,\s*[\'"].*?\r\n', re.IGNORECASE), 
     'Potential HTTP Header Injection', 'High', 'Ensure HTTP headers do not include unvalidated user input to prevent header injection.'),


    # Java and Spring Boot Specific Findings Check.
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
    (re.compile(r'management\.endpoints\.web\.exposure\.include\s*=\s*\*', re.IGNORECASE),
     'Exposed Actuator Endpoints', 'High', 'Restrict exposure of actuator endpoints in production, and secure sensitive endpoints with authentication.'),
    (re.compile(r'spring\.web\.cors\.allowed-origins\s*=\s*\*', re.IGNORECASE),
     'Insecure CORS Configuration', 'High', 'Restrict CORS origins to trusted domains only.'),
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
    (re.compile(r'server\.ssl\.enabled\s*=\s*false', re.IGNORECASE), 
     'SSL/TLS Disabled', 'High', 'Enable SSL/TLS to ensure secure communication over HTTPS.'),
    (re.compile(r'spring\.web\.cors\.allowed-origin-patterns\s*=\s*\*', re.IGNORECASE), 
     'CORS Policy Allows All Origins', 'High', 'Restrict CORS to only trusted domains. Avoid using wildcard (*) in production.'),
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
    (re.compile(r'spring\.security\.oauth2\.client\.registration\..*\.client-id\s*=\s*.*', re.IGNORECASE),'Exposed OAuth2 Client ID', 'Medium', 'Keep client IDs secure and do not expose them in application properties.'),
    (re.compile(r'new\s+HttpURLConnection\s*\(.*[+].*\)', re.IGNORECASE),
     'Potential HTTP Request Injection', 'High', 'Avoid constructing HTTP requests with concatenated strings; sanitize inputs properly.'),
    (re.compile(r'InputStreamReader\s*\(\s*new\s+FileInputStream\s*\(.*\)\s*\)', re.IGNORECASE),
     'Potential Insecure File Input', 'High', 'Avoid reading files without proper validation and sanitization of file paths.'),
    (re.compile(r'spring\.security\.csrf\.enabled\s*=\s*false', re.IGNORECASE),
     'CSRF Protection Disabled', 'High', 'Enable CSRF protection for all forms or secure endpoints requiring stateful interactions.'),
    (re.compile(r'Content-Security-Policy\s*:\s*default-src\s+.*;', re.IGNORECASE),
     'Weak Content Security Policy (CSP)', 'Medium', 'Define a strict CSP to prevent unauthorized resource loading and mitigate XSS risks.'),
    (re.compile(r'server\.ssl\.enabled\s*=\s*false', re.IGNORECASE),
     'SSL/TLS Disabled', 'High', 'Enable SSL/TLS to ensure secure communication over HTTPS.'),
    (re.compile(r'spring\.web\.cors\.allowed-origin-patterns\s*=\s*\*', re.IGNORECASE),
     'CORS Policy Allows All Origins', 'High', 'Restrict CORS to only trusted domains. Avoid using wildcard (*) in production.'),
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
     'Potential SQL Injection with String Concatenation', 'High', 'Avoid concatenating strings for SQL queries; use parameterized queries instead.'),

     



    # Insecure URLs and Endpoints
    (re.compile(r'(?i)http:\/\/[^\s]+'), 
     'Insecure HTTP URL', 'Medium', 'Use HTTPS for secure connections.'),

    # Debugging and Development Information
    (re.compile(r'(?i)(debug|development)[\s:=]+(true|1)', re.IGNORECASE), 
     'Debug Mode Enabled', 'Medium', 'Ensure debug mode is disabled in production.'),

    # IP Address Exposure
    (re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'), 
     'IP Address Exposure', 'Medium', 'Ensure IP addresses are masked or redacted if not necessary.'),

    # Sensitive Data in Logs
    (re.compile(r'(print|console\.log|logger\.info|logger\.debug|logging\.info)\s*\(.*?(api[_-]?key|secret|token|password|passwd|jwt).*\)', re.IGNORECASE), 
     'Sensitive Data in Logs', 'High', 'Do not log sensitive data.'),


    # Miscellaneous Sensitive Data and Information Disclosures
    (re.compile(r'(?i)(app[_-]?secret|app[_-]?id|client[_-]?id|client[_-]?secret)[\s:=]+[\'"]?[\w-]{16,}[\'"]?'), 
     'Hardcoded Application Secret', 'High', 'Move application secrets to environment variables.'),
    (re.compile(r'(?i)(aws[_-]?access[_-]?key[_-]?id)[\s:=]+[\'"]?[A-Z0-9]{20}[\'"]?', re.IGNORECASE), 
     'Hardcoded AWS Access Key ID', 'High', 'Move AWS access keys to environment variables or secure vaults.'),
    (re.compile(r'(?i)(aws[_-]?secret[_-]?access[_-]?key)[\s:=]+[\'"]?[A-Za-z0-9/+=]{40}[\'"]?', re.IGNORECASE), 
     'Hardcoded AWS Secret Access Key', 'High', 'Store AWS secret keys in a secure vault or environment variable.'),
    (re.compile(r'(?i)(db[_-]?username|database[_-]?user)[\s:=]+[\'"]?[a-zA-Z0-9_]{4,}[\'"]?', re.IGNORECASE), 
     'Hardcoded Database Username', 'Medium', 'Store database usernames in secure configuration settings or environment variables.'),
    (re.compile(r'(?i)(google[_-]?api[_-]?key)[\s:=]+[\'"]?[A-Za-z0-9-_]{39}[\'"]?', re.IGNORECASE), 
     'Hardcoded Google API Key', 'High', 'Move Google API keys to environment variables or secure vaults.'),
    (re.compile(r'(?i)(slack[_-]?webhook[_-]?url)[\s:=]+[\'"]?https://hooks.slack.com/services/[A-Za-z0-9/_-]+[\'"]?', re.IGNORECASE), 
     'Hardcoded Slack Webhook URL', 'High', 'Store Slack webhook URLs securely and avoid hardcoding them.'),
    (re.compile(r'(?i)(twilio[_-]?api[_-]?key)[\s:=]+[\'"]?[A-Za-z0-9]{32}[\'"]?', re.IGNORECASE), 
     'Hardcoded Twilio API Key', 'High', 'Move Twilio API keys to secure environment variables.'),
    (re.compile(r'(?i)(sendgrid[_-]?api[_-]?key)[\s:=]+[\'"]?[A-Za-z0-9]{22}[\'"]?', re.IGNORECASE), 
     'Hardcoded SendGrid API Key', 'High', 'Store SendGrid API keys in environment variables or secure vaults.'),
    (re.compile(r'(?i)(facebook[_-]?access[_-]?token)[\s:=]+[\'"]?EAACEdEose0cBA[0-9A-Za-z]{30,}[\'"]?', re.IGNORECASE), 
     'Hardcoded Facebook Access Token', 'High', 'Avoid hardcoding Facebook tokens; store them securely in environment variables.'),
    (re.compile(r'(?i)(github[_-]?token)[\s:=]+[\'"]?[A-Za-z0-9_]{40}[\'"]?', re.IGNORECASE), 
     'Hardcoded GitHub Personal Access Token', 'High', 'Store GitHub tokens securely and avoid hardcoding them.'),
    (re.compile(r'(?i)(stripe|paypal)[_-]?(secret|client)[_-]?key[\s:=]+[\'"]?[A-Za-z0-9_]{32,}[\'"]?', re.IGNORECASE), 
     'Hardcoded Payment Processor Secret Key', 'High', 'Move payment processor keys to secure storage or environment variables.'),
    (re.compile(r'(?i)firebase[_-]?secret[\s:=]+[\'"]?[A-Za-z0-9_]{32,}[\'"]?', re.IGNORECASE), 
     'Hardcoded Firebase Secret', 'High', 'Avoid hardcoding Firebase secrets; store them securely in environment variables.'),
    (re.compile(r'(?i)(private[_-]?api[_-]?key)[\s:=]+[\'"]?[A-Za-z0-9-_]{16,}[\'"]?', re.IGNORECASE), 
     'Hardcoded Private API Key', 'High', 'Move private API keys to environment variables or secure storage.'),
    (re.compile(r'(?i)oauth[_-]?client[_-]?secret[\s:=]+[\'"]?[A-Za-z0-9-_]{32,}[\'"]?', re.IGNORECASE), 
     'Hardcoded OAuth Client Secret', 'High', 'Avoid hardcoding OAuth client secrets; store them in a secure vault.'),
    (re.compile(r'(?i)instagram[_-]?access[_-]?token[\s:=]+[\'"]?[A-Za-z0-9]{32}[\'"]?', re.IGNORECASE), 
     'Hardcoded Instagram Access Token', 'High', 'Move Instagram access tokens to secure environment variables or vaults.'),
    (re.compile(r'(?i)service[_-]?account[_-]?(key|secret)[\s:=]+[\'"]?[A-Za-z0-9-_]{16,}[\'"]?', re.IGNORECASE), 
     'Hardcoded Service Account Key', 'High', 'Store service account keys in secure storage instead of hardcoding them.'),
    (re.compile(r'(?i)azure[_-]?tenant[_-]?id[\s:=]+[\'"]?[A-Za-z0-9-_]{36}[\'"]?', re.IGNORECASE), 
     'Hardcoded Microsoft Azure Tenant ID', 'Medium', 'Avoid hardcoding Azure tenant IDs; use secure configuration settings.'),
    (re.compile(r'(?i)ldap[_-]?bind[_-]?password[\s:=]+[\'"]?[a-zA-Z0-9_]{8,}[\'"]?', re.IGNORECASE), 
     'Hardcoded LDAP Bind Password', 'High', 'Store LDAP bind passwords securely in environment variables or vaults.'),
    (re.compile(r'(?i)jwt[_-]?secret[_-]?key[\s:=]+[\'"]?[A-Za-z0-9-_]{32,}[\'"]?', re.IGNORECASE), 
     'Hardcoded JWT Secret Key', 'High', 'Store JWT secrets securely in environment variables or secure storage.'),
    (re.compile(r'ey[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+'), 
     'Hardcoded JWT Token', 'High', 'Avoid hardcoding JWT tokens; use secure session storage mechanisms.'),
    (re.compile(r'https?:\/\/[^\s]+:[^\s]+@[^\s]+', re.IGNORECASE), 
     'API Endpoint with Embedded Credentials', 'High', 'Avoid embedding credentials in URLs; use secure storage methods for authentication.'),
    (re.compile(r'(?i)ibm[_-]?cloud[_-]?api[_-]?key[\s:=]+[\'"]?[A-Za-z0-9-_]{32,}[\'"]?', re.IGNORECASE), 
     'Hardcoded IBM Cloud API Key', 'High', 'Move IBM Cloud API keys to secure environment variables or vaults.'),


    # Control Flow Detection Patterns
    (re.compile(r'if\s*\(.*?auth.*?\)|if\s*\(.*?login.*?\)', re.IGNORECASE), 
     'Authentication/Authorization Check', 'Informational', 'Check if access is restricted to authenticated users.'),
    (re.compile(r'if\s*\(.*?isAdmin.*?\)|if\s*\(.*?role.*?\)', re.IGNORECASE), 
     'Role-Based Access Control Check', 'Informational', 'Ensure access control based on user roles is enforced.'),
    (re.compile(r'if\s*\(.*?elevate.*?\)|if\s*\(.*?privilege.*?\)', re.IGNORECASE), 
     'Privilege Escalation Check', 'High', 'Ensure that privilege escalation checks are properly handled and logged.'),
    (re.compile(r'if\s*\(.*?accessLevel.*?\)|if\s*\(.*?permission.*?\)', re.IGNORECASE), 
     'Access Level Verification', 'Medium', 'Verify that access levels are appropriately checked to prevent unauthorized access.'),
    (re.compile(r'if\s*\(.*?hasPermission.*?\)|if\s*\(.*?canAccess.*?\)', re.IGNORECASE), 
     'Permission Check', 'Informational', 'Ensure permission checks are in place to restrict unauthorized access.'),
    (re.compile(r'if\s*\(.*?token.*?\)|if\s*\(.*?isValidToken.*?\)', re.IGNORECASE), 
     'Token Validation Check', 'High', 'Ensure that token validations are securely implemented to prevent bypasses.'),
    (re.compile(r'if\s*\(.*?session.*?\)|if\s*\(.*?isValidSession.*?\)', re.IGNORECASE), 
     'Session Validation Check', 'Medium', 'Verify that session validations are properly managed to prevent session hijacking.'),
    (re.compile(r'if\s*\(.*?mfa.*?\)|if\s*\(.*?twoFactor.*?\)', re.IGNORECASE), 
     'Multi-Factor Authentication Check', 'High', 'Ensure MFA checks are required for sensitive actions or access levels.'),
    (re.compile(r'if\s*\(.*?isActive.*?\)|if\s*\(.*?isSuspended.*?\)', re.IGNORECASE), 
     'User Status Check', 'Medium', 'Verify that only active users are granted access to functionalities.'),
    (re.compile(r'if\s*\(.*?securityGroup.*?\)', re.IGNORECASE), 
     'Security Group Validation', 'Medium', 'Ensure that access is controlled based on security group memberships.'),
    (re.compile(r'if\s*\(.*?isOwner.*?\)', re.IGNORECASE), 
     'Resource Ownership Check', 'Medium', 'Check that only resource owners have permission to modify their resources.'),
    (re.compile(r'if\s*\(.*?whitelistedIp.*?\)|if\s*\(.*?trustedIp.*?\)', re.IGNORECASE), 
     'IP Whitelisting Check', 'Medium', 'Verify that IP whitelisting logic is correctly implemented to restrict access.'),
    (re.compile(r'if\s*\(.*?rateLimit.*?\)|if\s*\(.*?throttle.*?\)', re.IGNORECASE), 
     'Rate Limiting or Throttling Check', 'Informational', 'Ensure rate limiting and throttling are enforced to prevent abuse.'),
    (re.compile(r'if\s*\(.*?userRole.*?\)|if\s*\(.*?groupMember.*?\)', re.IGNORECASE), 
     'User Role/Group Membership Check', 'Medium', 'Verify that access control is properly enforced based on role or group membership.'),
    (re.compile(r'if\s*\(.*?isSecureConnection.*?\)|if\s*\(.*?httpsOnly.*?\)', re.IGNORECASE), 
     'Secure Connection Requirement Check', 'High', 'Ensure that secure (HTTPS) connections are enforced for sensitive actions.'),
    (re.compile(r'if\s*\(.*?accountLocked.*?\)|if\s*\(.*?isSuspended.*?\)', re.IGNORECASE), 
     'Account Lockout/Suspension Check', 'High', 'Ensure locked or suspended accounts cannot access restricted functionalities.'),
    (re.compile(r'if\s*\(.*?tokenExpired.*?\)|if\s*\(.*?isTokenValid.*?\)', re.IGNORECASE), 
     'Access Token Expiration Check', 'High', 'Verify that expired tokens are invalidated and access is denied.'),


    # Vulnerable Dependency Detection Patterns
    (re.compile(r'"express"\s*:\s*"[^4]\.\d+\.\d+"', re.IGNORECASE), 
     'Vulnerable Express Version (Node.js)', 'High', 'Update Express to the latest version, ideally 4.x or above.'),
    (re.compile(r'"lodash"\s*:\s*"(?:3\.\d+\.\d+|4\.(?:[0-9]|1[0-6])\.\d+)"', re.IGNORECASE), 
     'Vulnerable lodash Version (Node.js)', 'High', 'Update lodash to the latest version (4.17.0 or higher) to avoid vulnerabilities.'),
    (re.compile(r'Django\s*==\s*(1\.\d+\.\d+|2\.(?:[0-1])\.\d+)', re.IGNORECASE), 
     'Vulnerable Django Version (Python)', 'High', 'Upgrade Django to the latest stable version (2.2.x LTS or 3.x) to address security issues.'),
    (re.compile(r'Flask\s*==\s*(0\.\d+\.\d+|1\.[0-1]\.\d+)', re.IGNORECASE), 
     'Vulnerable Flask Version (Python)', 'High', 'Upgrade Flask to version 1.1.1 or higher to address security issues.'),
    (re.compile(r'requests\s*==\s*2\.(?:[0-9]|1[0-8])\.\d+', re.IGNORECASE), 
     'Vulnerable Requests Version (Python)', 'Medium', 'Upgrade requests to 2.20.0 or higher to mitigate security risks.'),
    (re.compile(r'<version>(4\.\d+\.\d+|5\.[0-1]\.\d+)</version>\s*<!--\s*Spring Framework\s*-->', re.IGNORECASE), 
     'Vulnerable Spring Framework Version (Java)', 'High', 'Update Spring Framework to 5.2.x or higher to address known vulnerabilities.'),
    (re.compile(r'<artifactId>jackson-databind</artifactId>\s*<version>(2\.(?:[0-9]|1[0-8])\.\d+)</version>', re.IGNORECASE), 
     'Vulnerable Jackson Databind Version (Java)', 'High', 'Upgrade jackson-databind to version 2.9.9.3 or higher to avoid CVEs.'),
    (re.compile(r'rails\s*\(\s*(3\.\d+\.\d+|4\.\d+\.\d+|5\.[0-1]\.\d+)\s*\)', re.IGNORECASE), 
     'Vulnerable Rails Version (Ruby)', 'High', 'Update Rails to the latest version, ideally 5.2.x or higher.'),
    (re.compile(r'"laravel/framework"\s*:\s*"(5\.[0-3]\.\d+|5\.4\.\d+)"', re.IGNORECASE), 
     'Vulnerable Laravel Version (PHP)', 'High', 'Upgrade Laravel to version 5.5 or higher to fix known vulnerabilities.'),
    (re.compile(r'"symfony/symfony"\s*:\s*"(2\.\d+\.\d+|3\.\d+\.\d+)"', re.IGNORECASE), 
     'Vulnerable Symfony Version (PHP)', 'High', 'Upgrade Symfony to version 4.x or higher for better security.'),
    (re.compile(r'"jquery"\s*:\s*"(1\.\d+\.\d+|2\.\d+\.\d+)"', re.IGNORECASE), 
     'Vulnerable jQuery Version', 'High', 'Use jQuery version 3.5.0 or later to avoid security issues.'),
    (re.compile(r'<artifactId>log4j</artifactId>\s*<version>(1\.\d+\.\d+|2\.(?:0\.[0-9]|1\.[0-9]|10\.0))</version>', re.IGNORECASE), 
     'Vulnerable Log4j Version (Java)', 'Critical', 'Update Log4j to 2.11.1 or higher due to severe security vulnerabilities.'),
    (re.compile(r'"axios"\s*:\s*"(0\.[0-1]\.\d+|0\.1[0-8]\.\d+)"', re.IGNORECASE), 
     'Vulnerable Axios Version (Node.js)', 'High', 'Upgrade Axios to 0.19.0 or later to avoid security risks.'),
    (re.compile(r'devise\s*\(\s*3\.\d+\.\d+\s*\)', re.IGNORECASE), 
     'Vulnerable Devise Gem Version (Ruby)', 'High', 'Update Devise to version 4.x or higher to mitigate vulnerabilities.'),
    (re.compile(r'SQLAlchemy\s*==\s*0\.\d+\.\d+', re.IGNORECASE), 
     'Vulnerable SQLAlchemy Version (Python)', 'High', 'Upgrade SQLAlchemy to 1.3.x or higher to avoid security vulnerabilities.'),
    (re.compile(r'<artifactId>struts2-core</artifactId>\s*<version>(2\.[0-4]\.\d+|2\.5\.[0-9])</version>', re.IGNORECASE), 
     'Vulnerable Apache Struts Version (Java)', 'Critical', 'Update Apache Struts to 2.5.10 or higher to mitigate severe vulnerabilities.'),
    (re.compile(r'"angular"\s*:\s*"(1\.\d+\.\d+)"', re.IGNORECASE), 
     'Vulnerable AngularJS Version', 'High', 'Consider migrating to Angular 2+ or higher, as AngularJS 1.x is no longer supported.'),
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
    """Calculate MD5 hash of a file for change detection, handling errors gracefully."""
    hasher = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            hasher.update(f.read())
        return hasher.hexdigest()
    except FileNotFoundError:
        logging.error(f"File not found for hashing: {file_path}")
    except PermissionError:
        logging.error(f"Permission denied when accessing file: {file_path}")
    except Exception as e:
        logging.error(f"Unexpected error calculating hash for file {file_path}: {e}")
    return None  # Return None if hash calculation fails

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
        except FileNotFoundError:
            logging.error(f"Cache file not found: {CACHE_FILE}")
        except PermissionError:
            logging.error(f"Permission denied when accessing cache file: {CACHE_FILE}")
        except Exception as e:
            logging.error(f"Unexpected error loading hashes from cache file {CACHE_FILE}: {e}")
    else:
        logging.info(f"Cache file {CACHE_FILE} does not exist. Starting with empty hash list.")
    return hashes

def save_current_hashes(hashes):
    """Save current file hashes after scanning, handling file errors."""
    try:
        with open(CACHE_FILE, 'w') as f:
            for file_path, file_hash in hashes.items():
                f.write(f"{file_path},{file_hash}\n")
    except PermissionError:
        logging.error(f"Permission denied when trying to write to cache file: {CACHE_FILE}")
    except Exception as e:
        logging.error(f"Unexpected error saving hashes to cache file {CACHE_FILE}: {e}")

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
                    try:
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
                    except re.error as re_err:
                        logging.warning(f"Regex error for pattern '{pattern}' in file {file_path} at line {line_number}: {re_err}")
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
    return matches

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

def scan_pom(file_path: str):
    """Parse pom.xml file to extract dependencies and log them with dependency tree analysis, handling parsing errors."""
    try:
        tree = etree.parse(file_path)
        dependencies = tree.xpath('//dependency')
        for dep in dependencies:
            group_id = dep.findtext('groupId', 'Unknown')
            artifact_id = dep.findtext('artifactId', 'Unknown')
            version = dep.findtext('version', 'Unknown')
            logging.info(f"Dependency in {file_path}: Group: {group_id}, Artifact: {artifact_id}, Version: {version}")
    except etree.XMLSyntaxError as xml_err:
        logging.error(f"XML syntax error parsing pom.xml file {file_path}: {xml_err}")
    except Exception as e:
        logging.error(f"Unexpected error parsing pom.xml file {file_path}: {e}")

def get_code_snippet(file_path, line_number, context=3):
    """Return code snippet around a matched line for context, handling file errors."""
    snippet = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            lines = file.readlines()
            start = max(line_number - context - 1, 0)
            end = min(line_number + context, len(lines))
            snippet = ''.join(lines[start:end])
    except FileNotFoundError:
        logging.error(f"File not found when attempting to get snippet: {file_path}")
    except PermissionError:
        logging.error(f"Permission denied when attempting to read file: {file_path}")
    except Exception as e:
        logging.error(f"Unexpected error getting snippet from {file_path} at line {line_number}: {e}")
    return snippet

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

# At the beginning of scan_directory
def scan_directory(directory: str, previous_hashes):
    """Scan a directory for security vulnerabilities, handling errors in directory traversal and file processing."""
    print(f"Scanning directory: {directory}")
    current_hashes = {}
    findings = []

    # Log each file being processed
    with ThreadPoolExecutor() as executor:
        futures = []
        try:
            for root, _, files in os.walk(directory):
                if any(ignored in root for ignored in IGNORE_LIST):
                    continue
                for file in files:
                    file_path = os.path.join(root, file)
                    print(f"Scanning file: {file_path}")  # Log each file
                    if file.endswith(('.java', '.properties', '.xml', '.py', '.js', '.yml', '.json')):
                        futures.append(executor.submit(scan_file, file_path, previous_hashes, current_hashes))

            for future in futures:
                try:
                    findings.extend(future.result())
                except Exception as e:
                    logging.error(f"Error in thread execution for file scanning task: {e}")

        except Exception as e:
            logging.error(f"Unexpected error while scanning directory {directory}: {e}")

    save_current_hashes(current_hashes)
    findings.extend(track_data_flow())
    return findings

def export_to_csv(findings, filename="security_scan_report.csv"):
    """Export findings to a CSV report, with error handling for file operations."""
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
    except PermissionError:
        logging.error(f"Permission denied when trying to write to CSV file: {filename}")
    except Exception as e:
        logging.error(f"Unexpected error exporting findings to CSV file {filename}: {e}")

init(autoreset=True)  # Initialize colorama with auto-reset for colors

def print_findings(findings):
    """Print findings to the console with color coding based on severity, handling missing data gracefully."""
    for finding in findings:
        try:
            severity = finding.get('severity', 'UNKNOWN').upper()
            
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
            print(f"{color}{indicator} {finding.get('description', 'No description provided')}{Style.RESET_ALL}")
            print(f"{color}    - File: {finding.get('file', 'Unknown file')}{Style.RESET_ALL}")
            print(f"{color}    - Line: {finding.get('line', 'N/A')}{Style.RESET_ALL}")
            print(f"{color}    - Severity: {severity}{Style.RESET_ALL}")
            print(f"{color}    - Suggested Fix: {finding.get('fix_suggestion', 'N/A')}{Style.RESET_ALL}")
            print(f"{color}    - Code Snippet: {finding.get('snippet', '').strip()}{Style.RESET_ALL}")
            print()  # Blank line for readability
        except Exception as e:
            logging.error(f"Error printing finding: {e}")
            print("An error occurred while displaying this finding. Check logs for details.")

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

def main():
    """Main function to parse CLI arguments and run the scan with error handling."""
    try:
        parser = argparse.ArgumentParser(description="Scan codebase for security vulnerabilities.")
        parser.add_argument('directory', type=str, help='Path to the directory to scan')
        parser.add_argument('--format', choices=['html', 'csv', 'both'], default='both', help='Output report format')
        args = parser.parse_args()

        # Load previous hashes and handle potential errors
        try:
            previous_hashes = load_previous_hashes()
        except Exception as e:
            logging.error(f"Error loading previous hashes: {e}")
            print("Failed to load previous hashes. Continuing without previous hash data.")
            previous_hashes = {}  # Use an empty dictionary if loading fails

        # Run the scan and handle potential errors
        try:
            findings = scan_directory(args.directory, previous_hashes)
            print_findings(findings)
            print(f"Total findings: {len(findings)}")
        except Exception as e:
            logging.error(f"Error scanning directory: {e}")
            print("An error occurred during the scan. Please check the logs for more details.")
            findings = []  # Use an empty list if scanning fails

        # Export findings based on selected format with error handling for each format
        if findings:
            if args.format in ['csv', 'both']:
                try:
                    export_to_csv(findings)
                    print("CSV report generated as 'security_scan_report.csv'.")
                except Exception as e:
                    logging.error(f"Error exporting to CSV: {e}")
                    print("Failed to generate CSV report. Please check the logs for details.")

            if args.format in ['html', 'both']:
                try:
                    export_to_html(findings)
                    print("HTML report generated as 'security_scan_report.html'.")
                except Exception as e:
                    logging.error(f"Error exporting to HTML: {e}")
                    print("Failed to generate HTML report. Please check the logs for details.")
        else:
            print("No findings to export.")

        print("Scan complete. Reports are saved in the specified format(s).")

    except Exception as e:
        logging.error(f"Unexpected error in main function: {e}")
        print("An unexpected error occurred. Please check the logs for more details.")

if __name__ == "__main__":
    main()

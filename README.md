# Nuclei
Prompts

Authentication Bypass
Identify weak authentication mechanisms.

nuclei -target "TARGET" -ai "Identify login pages vulnerable to authentication bypass."
nuclei -target "TARGET" -ai "Identify improperly configured OAuth authentication mechanisms."
nuclei -target "TARGET" -ai "Scan for JWT vulnerabilities where authentication can be bypassed."
nuclei -target "TARGET" -ai "Detect weak or publicly exposed API keys leading to authentication bypass."
nuclei -target "TARGET" -ai "Identify authentication bypass vulnerabilities due to weak JWT token implementations."
nuclei -target "TARGET" -ai "Identify login pages vulnerable to authentication bypass."

Broken Access Control
Check for improper access control that allows unauthorized actions.

nuclei -target "TARGET" -ai "Identify cases where unauthorized users can access privileged resources by modifying URLs."
nuclei -target "TARGET" -ai "Scan for access control vulnerabilities that allow unauthorized access."
nuclei -target "TARGET" -ai "Detect improper user authorization and privilege escalation vulnerabilities."

Command Injection
Find vulnerabilities where commands can be injected through user input.

nuclei -target "TARGET" -ai "Identify user input fields allowing shell command execution."

Directory Traversal
Detect path traversal vulnerabilities.

nuclei -target "TARGET" -ai "Check for traversal vulnerabilities allowing PHP file inclusion."
nuclei -target "TARGET" -ai "Identify directory traversal vulnerabilities using Windows-style file paths."
nuclei -target "TARGET" -ai "Find vulnerabilities where absolute file paths can be exploited for unauthorized access."
nuclei -target "TARGET" -ai "Identify directory traversal vulnerabilities allowing access to sensitive files."
nuclei -target "TARGET" -ai "Detect sensitive files exposed via traversal attacks."


File Inclusion (LFI/RFI)
Identify Local and Remote File Inclusion vulnerabilities.

nuclei -target "TARGET" -ai "Check for Local and Remote File Inclusion vulnerabilities in file upload and inclusion mechanisms."\



Hardcoded Credentials
Hardcoded credentials refer to sensitive authentication data such as usernames, passwords, API keys, or tokens that are directly embedded in source code. Attackers can easily extract these credentials from repositories, config files, or application binaries, leading to unauthorized access and security breaches

nuclei -target "TARGET" -ai "Scan js files and search for endpoints that includes parameters"
nuclei -target "TARGET" -ai "Scan for plaintext passwords stored in environment files and config files."
nuclei -target "TARGET" -ai "Detect hardcoded API keys left inside JavaScript, Python, and other language files."
nuclei -target "TARGET" -ai "Scan for AWS, Google Cloud, and Azure credentials embedded in source files."
nuclei -target "TARGET" -ai "Identify hardcoded JSON Web Token (JWT) secrets that can be exploited for authentication bypass."
nuclei -target "TARGET" -ai "Detect SSH private keys left in public repositories or web directories."
nuclei -target "TARGET" -ai "Identify hardcoded database usernames and passwords in backend source code."
nuclei -target "TARGET" -ai "Scan for exposed API keys in source code, configuration files, and logs."

HTTP Request Smuggling
Find vulnerabilities in HTTP request parsing that allow header manipulation.


nuclei -target "TARGET" -ai "Find HTTP request smuggling vulnerabilities by testing different content-length and transfer encoding headers."

Insecure Direct Object References (IDOR)
Identify direct object reference issues leading to unauthorized data access.

nuclei -target "TARGET" -ai "Detect insecure direct object references exposing unauthorized data."

JWT Token Vulnerabilities
Detect weak implementations of JSON Web Tokens.

nuclei -target "TARGET" -ai "Check for weak JWT implementations and misconfigurations."

Race Condition
Detect vulnerabilities related to race conditions in web applications.

nuclei -target "TARGET" -ai "Identify vulnerabilities where multiple parallel processes can manipulate shared resources."

Remote Code Execution (RCE)
Identify remote command execution weaknesses.

nuclei -target "TARGET" -ai "Scan for insecure file upload mechanisms that allow RCE."
nuclei -target "TARGET" -ai "Identify unsafe function calls that may lead to remote command execution."
nuclei -target "TARGET" -ai "Detect RCE vulnerabilities through insecure file upload mechanisms."
nuclei -target "TARGET" -ai "Identify potential command injection vulnerabilities in input fields."
nuclei -target "TARGET" -ai "Find potential remote command execution in input fields."

Security Misconfiguration
Identify security misconfigurations in web applications and servers.

nuclei -target "TARGET" -ai "Identify outdated or vulnerable software, including web servers, frameworks, and third-party libraries, by checking for known CVEs, deprecated versions, and security misconfigurations."
nuclei -target "TARGET" -ai "Detect the real IP address of a website protected by Cloudflare by analyzing misconfigurations, exposed headers, DNS records, and historical data leaks."
nuclei -target "TARGET" -ai "Find cloud storage misconfigurations exposing sensitive data."
nuclei -target "TARGET" -ai "Identify web applications exposing admin panels without authentication."
nuclei -target "TARGET" -ai "Identify missing security headers such as CSP, X-Frame-Options, and HSTS."
nuclei -target "TARGET" -ai "Scan for applications running with default credentials left unchanged."
nuclei -target "TARGET" -ai "Scan for default credentials, exposed directories, and insecure headers."


Server-Side Request Forgery (SSRF)
Detect SSRF vulnerabilities and insecure remote requests

nuclei -target "TARGET" -ai "Scan for SSRF vulnerabilities enabled due to misconfigured proxy servers."
nuclei -target "TARGET" -ai "Identify SSRF vulnerabilities that exploit insecure header handling."
nuclei -target "TARGET" -ai "Detect internal port scanning vulnerabilities using SSRF payloads."
nuclei -target "TARGET" -ai "Identify SSRF vulnerabilities that allow open redirection to attacker-controlled servers."
nuclei -target "TARGET" -ai "Find SSRF vulnerabilities allowing remote server requests."


SQL Injection
Find vulnerabilities related to SQL queries and database leaks.

nuclei -target "TARGET" -ai "Fuzz all parameters with sql injection detection payloads for mysql, mssql, postgresql, etc Use time base detection payloads"
nuclei -target "TARGET" -ai "Detect SQL injection vulnerabilities using time delay techniques."
nuclei -target "TARGET" -ai "Identify second-order SQL injection vulnerabilities where input is stored and executed later."
nuclei -target "TARGET" -ai "Identify SQL injection vulnerabilities using boolean-based conditions."
nuclei -target "TARGET" -ai "Check for error messages revealing SQL queries."
nuclei -target "TARGET" -ai "Detect SQL injection vulnerabilities where UNION statements can be leveraged to extract data."
nuclei -target "TARGET" -ai "Use time-based techniques to find blind SQL injection."


XML External Entity (XXE)
Detect XML External Entity (XXE) vulnerabilities.

nuclei -target "TARGET" -ai "Identify XML External Entity attacks in web applications accepting XML input."

XSS (Cross-Site Scripting)
Detect JavaScript injection vulnerabilities.

 nuclei -target "TARGET" -ai "Scan for XSS vulnerabilities inside inline event handlers such as onmouseover, onclick."
 nuclei -target "TARGET" -ai "Scan for XSS vulnerabilities inside inline event handlers such as onmouseover, onclick."
 nuclei -target "TARGET" -ai "Identify XSS vulnerabilities that bypass common web application firewalls."
 nuclei -target "TARGET" -ai "Identify XSS vulnerabilities that bypass common web application firewalls."
 nuclei -target "TARGET" -ai "Find DOM-based XSS vulnerabilities where user input is reflected inside JavaScript execution."
 nuclei -target "TARGET" -ai "Identify reflected XSS vulnerabilities via GET parameters."
 nuclei -target "TARGET" -ai "Find common XSS patterns in response bodies."
 

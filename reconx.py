import argparse
import asyncio
import os
import sys
import json
from termcolor import colored, cprint
import httpx # Import httpx here for use in main and ReconX class
from datetime import datetime # Import datetime for timestamping in reports
from urllib.parse import urlparse # Import urlparse for domain extraction

# Assume core modules are in 'core' directory
# Ensure these are implemented in your project for reconx.py to work correctly
from core.utils import setup_logging, get_random_user_agent
from core.scanner import Scanner
from core.detector import Detector
from core.endpoints import EndpointDiscoverer
from core.vulnerability import VulnerabilityMatcher
from core.ports import PortScanner
from core.subdomains import SubdomainEnumerator
from core.ssl_analysis import SSLAnalyzer
from core.headers import HeaderAnalyzer
from core.fuzzing import FuzzingEngine

# Assume integrations are in 'integrations' directory
from integrations.vulners_api import VulnersAPI
from integrations.exploitdb import ExploitDB
# from integrations.wappalyzer import WappalyzerIntegration # Uncomment if you implement
# from integrations.shodan import ShodanIntegration # Uncomment if you implement

# Assume plugins are in 'plugins' directory
from plugins.wordpress import WordPressPlugin
from plugins.joomla import JoomlaPlugin
from plugins.laravel import LaravelPlugin
from plugins.flask import FlaskPlugin

# Assume reports are in 'reports' directory
from reports.reporter import Reporter

# Artistic Banner for ReconX
RECONX_BANNER = """
   ██████╗ ███████╗███████╗ ██████╗███╗   ██╗██╗  ██╗
   ██╔══██╗██╔════╝██╔════╝██╔════╝████╗  ██║╚██╗██╔╝
   ██████╔╝█████╗  █████╗  ██║     ██╔██╗ ██║ ╚███╔╝
   ██╔══██╗██╔══╝  ██╔══╝  ██║     ██║╚██╗██║ ██╔██╗
   ██║  ██║███████╗███████╗╚██████╗██║ ╚████║██╔╝ ██╗
   ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═══╝╚═╝  ╚═╝

   Advanced Vulnerability Intelligence Scanner
   Unifying Recon, Scanning, and Reporting
"""

def clear_screen():
    """Clears the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

class ReconX:
    """
    ReconX: Advanced Vulnerability Intelligence Scanner.

    This class serves as the main orchestrator for the ReconX tool,
    managing the workflow of reconnaissance, scanning, and reporting.
    """
    def __init__(self, args):
        """
        Initializes the ReconX orchestrator with command-line arguments.
        Args:
            args (argparse.Namespace): Parsed command-line arguments.
        """
        self.args = args
        self.logger = setup_logging(args.verbose) # Initialize logging based on verbosity

        cprint(f"[*] ReconX initialized for target: {self.args.url}", "blue")

        # Initialize shared HTTPX client
        self.httpx_client = httpx.AsyncClient(
            timeout=30,
            follow_redirects=True,
            headers={"User-Agent": get_random_user_agent()}
        )

        # Load data files
        # Ensure 'data' directory and required files/subdirectories exist
        self.fingerprints = self._load_json_data(os.path.join("data", "fingerprints.json"))
        self.wordlists = {
            "subdomains": self._load_wordlist(os.path.join("data", "wordlists", "subdomains.txt")),
            "paths": self._load_wordlist(os.path.join("data", "wordlists", "paths.txt")),
            "fuzzing_xss": self._load_wordlist(os.path.join("data", "wordlists", "payloads", "xss.txt")),
            "fuzzing_sqli": self._load_wordlist(os.path.join("data", "wordlists", "payloads", "sqli.txt")),
            "fuzzing_lfi": self._load_wordlist(os.path.join("data", "wordlists", "payloads", "lfi.txt")),
            "fuzzing_rce": self._load_wordlist(os.path.join("data", "wordlists", "payloads", "rce.txt")),
            "fuzzing_open_redirect": self._load_wordlist(os.path.join("data", "wordlists", "payloads", "open_redirect.txt"))
        }
        cprint("[*] Data files (fingerprints, wordlists) loaded.", "blue")


        # Initialize core components
        self.scanner = Scanner(self.args, client=self.httpx_client)
        self.detector = Detector(self.args, client=self.httpx_client, fingerprints=self.fingerprints)
        # Pass max_crawl_depth to EndpointDiscoverer
        self.endpoint_discoverer = EndpointDiscoverer(self.args, client=self.httpx_client, common_paths=self.wordlists["paths"])
        self.vulnerability_matcher = VulnerabilityMatcher(self.args)
        self.port_scanner = PortScanner(self.args)
        self.subdomain_enumerator = SubdomainEnumerator(self.args, client=self.httpx_client, subdomain_wordlist=self.wordlists["subdomains"]) # Pass subdomain_wordlist
        self.ssl_analyzer = SSLAnalyzer(self.args, client=self.httpx_client)
        self.header_analyzer = HeaderAnalyzer(self.args, client=self.httpx_client)
        self.fuzzing_engine = FuzzingEngine(self.args, client=self.httpx_client, payloads={
            "xss": self.wordlists["fuzzing_xss"],
            "sqli": self.wordlists["fuzzing_sqli"],
            "lfi": self.wordlists["fuzzing_lfi"],
            "rce": self.wordlists["fuzzing_rce"],
            "open_redirect": self.wordlists["fuzzing_open_redirect"]
        })


        # Initialize integrations
        self.vulners_api = VulnersAPI(self.args, client=self.httpx_client) # Pass shared client
        self.exploitdb = ExploitDB(self.args, client=self.httpx_client) # Pass shared client
        # self.wappalyzer_integration = WappalyzerIntegration()
        # self.shodan_integration = ShodanIntegration()

        # Initialize plugins
        self.plugins = []
        if self.args.plugins.lower() == "all":
            self.plugins.extend([
                WordPressPlugin(self.args, client=self.httpx_client),
                JoomlaPlugin(self.args, client=self.httpx_client),
                LaravelPlugin(self.args, client=self.httpx_client),
                FlaskPlugin(self.args, client=self.httpx_client)
            ])
            cprint("[*] All plugins loaded.", "blue")
        else:
            enabled_plugins = [p.strip().lower() for p in self.args.plugins.split(',')]
            if "wordpress" in enabled_plugins:
                self.plugins.append(WordPressPlugin(self.args, client=self.httpx_client))
            if "joomla" in enabled_plugins:
                self.plugins.append(JoomlaPlugin(self.args, client=self.httpx_client))
            if "laravel" in enabled_plugins:
                self.plugins.append(LaravelPlugin(self.args, client=self.httpx_client))
            if "flask" in enabled_plugins:
                self.plugins.append(FlaskPlugin(self.args, client=self.httpx_client))
            cprint(f"[*] Loaded specific plugins: {', '.join(enabled_plugins)}", "blue")

        self.reporter = Reporter(self.args)


    def _load_json_data(self, file_path):
        """Loads JSON data from a file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            self.logger.error(f"Data file not found: {file_path}")
            return {}
        except json.JSONDecodeError:
            self.logger.error(f"Error decoding JSON from: {file_path}")
            return {}
        except Exception as e:
            self.logger.error(f"An unexpected error occurred loading JSON from {file_path}: {e}")
            return {}

    def _load_wordlist(self, file_path):
        """Loads wordlist from a file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            self.logger.warning(f"Wordlist file not found: {file_path}. Some features might be limited.")
            return []
        except Exception as e:
            self.logger.error(f"Error loading wordlist {file_path}: {e}")
            return []

    async def run(self):
        """
        Executes the main reconnaissance and scanning workflow.
        This method will orchestrate calls to various modules.
        """
        target_url = self.args.url
        base_domain = urlparse(target_url).netloc
        scan_results = {
            "target": target_url,
            "scan_date": None,
            "status": "In Progress",
            "technologies": {},
            "endpoints": [],
            "subdomains": [],
            "ports": {}, # Format: {"ip": [{"port": 80, "status": "open"}, ...]}
            "vulnerabilities": [], # Format: [{"technology": "...", "version": "...", "vulnerability": {...}}]
            "ssl_info": {},
            "headers_info": {},
            "fuzzing_results": [] # Format: [{"url": "...", "param": "...", "payload": "...", "payload_type": "..."}]
        }

        cprint(f"\n[+] Starting ReconX scan for: {target_url}", "green", attrs=["bold"])
        scan_results["scan_date"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # --- Phase 1: Technology Fingerprinting ---
        cprint("\n[+] Running Technology Fingerprinting...", "yellow")
        detected_technologies = await self.detector.fingerprint(target_url)
        if detected_technologies:
            scan_results["technologies"] = detected_technologies
            # Corrected f-string: removed extra comma and parenthesis
            cprint(f"    [+] Detected: {', '.join(f'{tech} v{info.get("version", "N/A")}' for tech, info in detected_technologies.items())}", "green")
        else:
            cprint("    [-] No major technologies detected.", "red")

        # --- Phase 2: Endpoint Discovery ---
        cprint("\n[+] Running Endpoint Discovery...", "yellow")
        endpoints = await self.endpoint_discoverer.discover(target_url, self.args.deep_crawl)
        if endpoints:
            scan_results["endpoints"] = list(set(endpoints)) # Remove duplicates
            cprint(f"    [+] Discovered {len(endpoints)} endpoints.", "green")
            if self.args.verbose:
                for ep in endpoints[:10]: # Print first 10 for brevity
                    self.logger.info(f"        - {ep}")
                if len(endpoints) > 10:
                    self.logger.info("        ...")
        else:
            cprint("    [-] No significant endpoints discovered.", "red")

        # --- Phase 3: Subdomain Enumeration ---
        if self.args.include_subdomains:
            cprint("\n[+] Running Subdomain Enumeration...", "yellow")
            subdomains = await self.subdomain_enumerator.enumerate(base_domain)
            if subdomains:
                scan_results["subdomains"] = list(set(subdomains))
                cprint(f"    [+] Discovered {len(subdomains)} subdomains.", "green")
                if self.args.verbose:
                    for sd in subdomains[:10]:
                        self.logger.info(f"        - {sd}")
                    if len(subdomains) > 10:
                        self.logger.info("        ...")
            else:
                cprint("    [-] No subdomains discovered.", "red")

        # --- Phase 4: Port Scanning ---
        if self.args.port_scan:
            cprint("\n[+] Running Port Scanning...", "yellow")
            target_ips = []

            # Resolve IP for the main target URL
            try:
                # Use httpx to get the resolved IP from the actual request
                # This is a bit of a hack; a dedicated DNS resolver is better but httpx can give us the connected host
                response = await self.httpx_client.head(target_url)
                if response.is_success or response.is_redirect:
                    ip = urlparse(str(response.url)).hostname # Get hostname from final URL
                    # Simple check if it's an IP address string
                    if all(part.isdigit() for part in ip.split('.')) and len(ip.split('.')) == 4:
                        target_ips.append(ip)
                    else:
                        # Fallback for resolving domain to IP
                        import socket
                        try:
                            resolved_ip = socket.gethostbyname(ip)
                            if resolved_ip not in target_ips:
                                target_ips.append(resolved_ip)
                        except socket.gaierror:
                            self.logger.warning(f"Could not resolve IP for {ip}")

            except httpx.RequestError as e:
                self.logger.error(f"HTTPX error resolving IP for {target_url}: {e}")
            except Exception as e:
                self.logger.error(f"Could not resolve IP for {target_url}: {e}")

            # Resolve IPs for discovered subdomains
            for sd in scan_results["subdomains"]:
                try:
                    import socket
                    ip = socket.gethostbyname(urlparse(sd).hostname)
                    if ip not in target_ips: # Avoid duplicates
                        target_ips.append(ip)
                except socket.gaierror:
                    self.logger.warning(f"Could not resolve IP for subdomain {sd}")
                except Exception as e:
                    self.logger.error(f"Error resolving IP for subdomain {sd}: {e}")

            target_ips = list(set(target_ips)) # Ensure unique IPs

            if target_ips:
                ports_scanned_results = await self.port_scanner.scan(target_ips)
                scan_results["ports"] = ports_scanned_results
                cprint(f"    [+] Port scan completed for {len(target_ips)} IPs.", "green")
                if self.args.verbose:
                    for ip, ports_info in ports_scanned_results.items():
                        self.logger.info(f"        IP: {ip}, Open Ports: {[p['port'] for p in ports_info if p['status'] == 'open']}")
            else:
                cprint("    [-] No IPs resolved for port scanning.", "red")


        # --- Phase 5: Plugin-specific Checks (Detection and Vulnerabilities) ---
        cprint("\n[+] Running Plugin-specific Checks...", "yellow")
        for plugin in self.plugins:
            plugin_name = plugin.__class__.__name__.replace("Plugin", "")
            cprint(f"    [+] Checking for {plugin_name}...", "cyan")
            plugin_detected_info = await plugin.detect(target_url)
            if plugin_detected_info and plugin_detected_info.get("detected"):
                cprint(f"        [+] {plugin_name} detected! Running specific checks...", "green")
                plugin_vulnerabilities = await plugin.run_specific_checks(target_url, plugin_detected_info)
                if plugin_vulnerabilities:
                    for pv in plugin_vulnerabilities:
                        scan_results["vulnerabilities"].append({
                            "technology": plugin_name,
                            "version": plugin_detected_info.get("version", "N/A"),
                            "vulnerability": pv
                        })
                        cprint(f"            [VULN] {pv.get('description')} (Severity: {pv.get('severity')})", "red")
                else:
                    cprint(f"            [INFO] No specific vulnerabilities found for {plugin_name}.", "green")
            else:
                cprint(f"        [-] {plugin_name} not detected.", "red")


        # --- Phase 6: Vulnerability Matching (Generic, CVE/ExploitDB) ---
        cprint("\n[+] Running Generic Vulnerability Matching (CVE/ExploitDB)...", "yellow")
        if self.args.compare_cve:
            for tech, info in scan_results["technologies"].items():
                version = info.get("version")
                if version and version != "N/A":
                    cprint(f"    [+] Matching {tech} v{version} against CVEs via Vulners...", "cyan")
                    cve_vulns = await self.vulners_api.search_software(tech, version) # Corrected method call
                    if cve_vulns:
                        for vuln in cve_vulns:
                            scan_results["vulnerabilities"].append({
                                "technology": tech,
                                "version": version,
                                "vulnerability": vuln
                            })
                            cprint(f"        [VULN] {vuln.get('description')} (CVE: {', '.join(vuln.get('cve', []))}, Severity: {vuln.get('severity')})", "red")
                    else:
                        cprint(f"        [INFO] No CVEs found for {tech} v{version} via Vulners.", "green")
                else:
                    cprint(f"    [INFO] Skipping CVE check for {tech} (no version detected).", "yellow")

        # --- Phase 7: SSL & Security Header Analysis ---
        cprint("\n[+] Running SSL/TLS Analysis...", "yellow")
        ssl_info = await self.ssl_analyzer.analyze(target_url)
        if ssl_info:
            scan_results["ssl_info"] = ssl_info
            if ssl_info.get("status") == "Success":
                cprint(f"    [+] SSL/TLS analysis successful. Status: {ssl_info.get('certificate_details', {}).get('expiry_status')}", "green")
                if ssl_info.get("warnings"):
                    cprint(f"        [WARN] SSL Warnings: {len(ssl_info['warnings'])}", "yellow")
                if ssl_info.get("errors"):
                    cprint(f"        [ERROR] SSL Errors: {len(ssl_info['errors'])}", "red")
            else:
                cprint(f"    [-] SSL/TLS analysis failed or connection issues: {ssl_info.get('status')}", "red")

        cprint("\n[+] Running Security Header Analysis...", "yellow")
        headers_info = await self.header_analyzer.analyze(target_url)
        if headers_info:
            scan_results["headers_info"] = headers_info
            if headers_info.get("missing_headers") or headers_info.get("insecure_headers") or headers_info.get("content_security_policy", {}).get("issues"):
                cprint(f"    [VULN] Security header issues detected. Missing: {len(headers_info.get('missing_headers', []))}, Insecure: {len(headers_info.get('insecure_headers', []))}", "red")
            else:
                cprint("    [+] No critical security header issues detected.", "green")

        # --- Phase 8: Fuzzing Engine ---
        if self.args.fuzz:
            cprint("\n[+] Running Fuzzing Engine...", "yellow")
            fuzz_results = await self.fuzzing_engine.fuzz(scan_results["endpoints"]) # Fuzzing targets discovered endpoints
            if fuzz_results:
                scan_results["fuzzing_results"] = fuzz_results
                cprint(f"    [VULN] Fuzzing found {len(fuzz_results)} potential vulnerabilities.", "red")
                if self.args.verbose:
                    for fr in fuzz_results:
                        self.logger.info(f"        - {fr.get('payload_type').upper()} at {fr.get('url')} (Payload: {fr.get('payload')})")
            else:
                cprint("    [+] Fuzzing completed, no vulnerabilities detected.", "green")

        # --- Final Status ---
        scan_results["status"] = "Completed"
        cprint(f"\n[+] ReconX scan for {target_url} completed.", "green", attrs=["bold"])

        # --- Phase 9: Reporting ---
        if not self.args.only_vuln:
            cprint(f"\n[+] Generating report in {self.args.output_format} format...", "yellow")
            self.reporter.generate_report(
                scan_results=scan_results,
                output_format=self.args.output_format,
                output_file=self.args.output_file if self.args.output_file else f"reconx_report_{base_domain}.{self.args.output_format}"
            )
            cprint(f"    [+] Report saved to: {self.args.output_file if self.args.output_file else f'reconx_report_{base_domain}.{self.args.output_format}'}", "green")
        else:
            cprint("\n[+] '--only-vuln' flag is set. Only showing critical vulnerabilities on console.", "yellow")
            # Filter and print only critical findings if --only-vuln is set
            critical_findings_present = False
            if scan_results["vulnerabilities"]:
                cprint("\n--- Identified Vulnerabilities ---", "red", attrs=["bold"])
                for vuln in scan_results["vulnerabilities"]:
                    cprint(f"[VULN] {vuln.get('technology', 'N/A')} v{vuln.get('version', 'N/A')}: {vuln['vulnerability'].get('description', 'N/A')} (Severity: {vuln['vulnerability'].get('severity', 'N/A')})", "red")
                    critical_findings_present = True
            if scan_results["fuzzing_results"]:
                cprint("\n--- Fuzzing Results ---", "red", attrs=["bold"])
                for fuzz_res in scan_results["fuzzing_results"]:
                    cprint(f"[FUZZ] {fuzz_res.get('payload_type').upper()} at {fuzz_res.get('url')} - {fuzz_res.get('details', [''])[0]}", "red")
                    critical_findings_present = True

            # Simplified check for header/SSL issues for --only-vuln
            if scan_results["headers_info"].get("missing_headers") or scan_results["headers_info"].get("insecure_headers") or \
               scan_results["headers_info"].get("content_security_policy", {}).get("issues"):
                cprint("[VULN] Security header misconfigurations detected.", "red")
                critical_findings_present = True

            if scan_results["ssl_info"].get("status") != "Success" or (scan_results["ssl_info"].get("status") == "Success" and scan_results["ssl_info"].get("warnings")):
                 cprint(f"[VULN] SSL/TLS issues detected: {scan_results['ssl_info'].get('status', 'N/A')}. Check report for details.", "red")
                 critical_findings_present = True

            if not critical_findings_present:
                cprint("\n[+] No critical vulnerabilities found based on '--only-vuln' criteria.", "green")


        # Close httpx client
        await self.httpx_client.aclose()
        cprint("[*] HTTPX client closed.", "blue")

def main():
    """
    Main function to parse arguments and run the ReconX tool.
    """
    # Clear the screen at the start
    os.system('cls' if os.name == 'nt' else 'clear')
    cprint(RECONX_BANNER, "cyan", attrs=["bold"]) # Print the banner

    parser = argparse.ArgumentParser(
        description=f"{colored('ReconX: Advanced Vulnerability Intelligence Scanner', 'cyan', attrs=['bold'])}\n"
                    f"{colored('A fast, modular, and comprehensive security assessment tool.', 'white')}",
        formatter_class=argparse.RawTextHelpFormatter
    )

    # Core arguments
    parser.add_argument(
        "-u", "--url",
        help=f"{colored('Target URL to scan (e.g., https://example.com)', 'white')}",
        type=str,
        required=True # Make URL required
    )
    parser.add_argument(
        "-o", "--output-file",
        help=f"{colored('Output file path for the report (e.g., report.html, report.json). If not specified, default name will be used.', 'white')}",
        type=str
    )
    parser.add_argument(
        "--output-format",
        help=f"{colored('Output report format (html, json, text). Default: html.', 'white')}",
        default="html",
        choices=["html", "json", "text"]
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help=f"{colored('Enable verbose output (more detailed logging).', 'white')}"
    )

    # Scanning options
    parser.add_argument(
        "--fast",
        action="store_true",
        help=f"{colored('Perform a fast scan (e.g., skip deep crawling, extensive port scans).', 'white')}"
    )
    parser.add_argument(
        "-d", "--deep-crawl", # Abbreviation added
        action="store_true",
        help=f"{colored('Enable deep crawling for endpoint discovery.', 'white')}"
    )
    parser.add_argument(
        "--max-crawl-depth", # Added max_crawl_depth argument
        type=int,
        default=2, # Default depth
        help=f"{colored('Maximum depth for deep crawling. Default: 2.', 'white')}"
    )
    parser.add_argument(
        "-s", "--include-subdomains", # Abbreviation added
        action="store_true",
        help=f"{colored('Include subdomain enumeration in the scan.', 'white')}"
    )
    parser.add_argument(
        "-p", "--port-scan", # Abbreviation added
        action="store_true",
        help=f"{colored('Perform port scanning on discovered assets.', 'white')}"
    )
    parser.add_argument(
        "-l", "--plugins", # Abbreviation added
        help=f"{colored('Comma-separated list of specific plugins to run (e.g., wordpress,joomla) or \'all\'. Default: all.', 'white')}",
        default="all",
        type=str
    )
    parser.add_argument(
        "-n", "--only-vuln", # Abbreviation added
        action="store_true",
        help=f"{colored('Only report identified vulnerabilities to console, suppress other information in report.', 'white')}"
    )
    parser.add_argument(
        "-c", "--compare-cve", # Abbreviation added
        action="store_true",
        help=f"{colored('Compare detected versions with CVE databases via Vulners API. Enabled by default if vulnerability matching is active.', 'white')}"
    )
    parser.add_argument(
        "-f", "--fuzz", # Abbreviation added
        action="store_true",
        help=f"{colored('Enable fuzzing for common vulnerabilities (XSS, SQLi, LFI, RCE, Open Redirect).', 'white')}"
    )

    args = parser.parse_args()

    # Ensure output file is specified if output format is not text and --only-vuln is not set
    if not args.only_vuln and args.output_format != "text" and not args.output_file:
        parsed_url = urlparse(args.url)
        # Use a sanitized version of the domain for the default filename
        safe_domain = "".join(c for c in parsed_url.netloc if c.isalnum() or c == '.')
        default_file_name = f"reconx_report_{safe_domain}.{args.output_format}"
        cprint(f"[*] No output file specified. Using default: {default_file_name}", "yellow")
        args.output_file = default_file_name

    # Initialize and run ReconX
    try:
        reconx = ReconX(args)
        asyncio.run(reconx.run())
    except ImportError as e:
        cprint(f"\n[ERROR] Missing required library: {e}. Please ensure all dependencies from requirements.txt are installed.", "red", attrs=["bold"])
        cprint("    To install: pip install -r requirements.txt", "cyan")
    except Exception as e:
        cprint(f"\n[CRITICAL ERROR] An unexpected error occurred: {e}", "red", attrs=["bold"])
        cprint("    Please ensure all necessary files (e.g., data/fingerprints.json, data/wordlists/*) exist and are correctly populated.", "yellow")
        if args.verbose:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()

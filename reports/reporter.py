import logging
import json
from typing import Dict, List, Any
from jinja2 import Environment, FileSystemLoader
import os
from datetime import datetime
from urllib.parse import urlparse

# Assuming core.utils is available for logging setup, though it's not strictly needed here
# from core.utils import setup_logging

class Reporter:
    """
    Generates structured reports in various formats (HTML, JSON, plain text)
    from the scan results.
    """
    def __init__(self, args=None):
        """
        Initializes the Reporter.
        Args:
            args (argparse.Namespace, optional): Command-line arguments.
                                                 Used for output format/file and verbose logging.
        """
        # setup_logging(args.verbose if args else False) # Set up logging for this module
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO) # Set a default level if not set by setup_logging
        if not self.logger.handlers: # Prevent adding handlers multiple times if already configured
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

        self.args = args
        # Configure Jinja2 environment to load templates from the 'templates' subdirectory
        # Assuming this script is in ReconX/reports/
        template_dir = os.path.join(os.path.dirname(__file__), "templates")
        self.env = Environment(loader=FileSystemLoader(template_dir))
        self.logger.debug(f"Jinja2 templates loaded from: {template_dir}")

    def _format_json_report(self, scan_results: Dict[str, Any]) -> str:
        """Formats scan results into a JSON string."""
        return json.dumps(scan_results, indent=4)

    def _format_text_report(self, scan_results: Dict[str, Any]) -> str:
        """Formats scan results into a plain text string."""
        report_lines = [f"--- ReconX Scan Report for {scan_results.get('target', 'N/A')} ---"]
        report_lines.append(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"Status: {scan_results.get('status', 'Unknown')}")
        report_lines.append("\n--- Technologies Detected ---")
        if scan_results.get("technologies"):
            for tech, info in scan_results["technologies"].items():
                version = info.get("version", "N/A")
                report_lines.append(f"- {tech} (Version: {version}, Source: {info.get('source', 'N/A')})")
        else:
            report_lines.append("No technologies detected.")

        report_lines.append("\n--- Endpoints Discovered ---")
        if scan_results.get("endpoints"):
            for ep in scan_results["endpoints"]:
                report_lines.append(f"- {ep}")
        else:
            report_lines.append("No endpoints discovered.")

        report_lines.append("\n--- Subdomains Discovered ---")
        if scan_results.get("subdomains"):
            for sd in scan_results["subdomains"]:
                report_lines.append(f"- {sd}")
        else:
            report_lines.append("No subdomains discovered.")

        report_lines.append("\n--- Open Ports ---")
        if scan_results.get("ports"):
            for host, ports in scan_results["ports"].items():
                report_lines.append(f"Host: {host}")
                if ports:
                    for p_info in ports:
                        report_lines.append(f"  - Port {p_info['port']}: {p_info['status']}")
                else:
                    report_lines.append("  No open ports detected.")
        else:
            report_lines.append("Port scan not performed or no open ports found.")

        report_lines.append("\n--- Vulnerabilities Identified ---")
        if scan_results.get("vulnerabilities"):
            for vuln_entry in scan_results["vulnerabilities"]:
                tech = vuln_entry.get('technology', 'N/A')
                version = vuln_entry.get('version', 'N/A')
                vuln_details = vuln_entry.get('vulnerability', {})
                report_lines.append(f"- [VULNERABLE] {tech} v{version}: {vuln_details.get('description', 'N/A')} (Severity: {vuln_details.get('severity', 'N/A')}, CVE: {', '.join(vuln_details.get('cve', [])) or 'N/A'})")
                if vuln_details.get('exploit_link'):
                    report_lines.append(f"  Exploit Link: {vuln_details['exploit_link']}")
        else:
            report_lines.append("No vulnerabilities identified.")

        report_lines.append("\n--- Security Headers Analysis ---")
        headers_info = scan_results.get("headers_info", {})
        report_lines.append(f"  Missing Headers: {len(headers_info.get('missing_headers', []))}")
        for h in headers_info.get('missing_headers', []):
            report_lines.append(f"    - {h.get('header')} (Severity: {h.get('severity')})")
        report_lines.append(f"  Insecure Headers: {len(headers_info.get('insecure_headers', []))}")
        for h in headers_info.get('insecure_headers', []):
            report_lines.append(f"    - {h.get('header')}: {h.get('value')} (Issue: {h.get('issue')}, Severity: {h.get('severity')})")
        csp_info = headers_info.get('content_security_policy', {})
        report_lines.append(f"  Content-Security-Policy: {'Present' if csp_info.get('present') else 'Missing'}")
        if csp_info.get('policy'):
            report_lines.append(f"    Policy: {csp_info['policy']}")
        for issue in csp_info.get('issues', []):
            report_lines.append(f"    CSP Issue: {issue}")
        report_lines.append(f"  CORS Status: {headers_info.get('cors_status', 'N/A')}")
        for warning in headers_info.get('warnings', []):
            report_lines.append(f"  Warning: {warning}")


        report_lines.append("\n--- SSL/TLS Analysis ---")
        ssl_info = scan_results.get("ssl_info", {})
        if ssl_info.get('status') == "Success":
            cert_details = ssl_info.get('certificate_details', {})
            report_lines.append(f"  Status: {ssl_info.get('status')}")
            report_lines.append(f"  TLS Version: {', '.join(ssl_info.get('tls_versions', []))}")
            report_lines.append(f"  Cipher Suites: {', '.join([c['name'] for c in ssl_info.get('cipher_suites', [])])}")
            report_lines.append(f"  Certificate Subject: {cert_details.get('subject', {}).get('commonName', 'N/A')}")
            report_lines.append(f"  Certificate Issuer: {cert_details.get('issuer', {}).get('commonName', 'N/A')}")
            report_lines.append(f"  Valid From: {cert_details.get('not_before')}")
            report_lines.append(f"  Valid Until: {cert_details.get('not_after')}")
            report_lines.append(f"  Expiry Status: {cert_details.get('expiry_status')}")
            report_lines.append(f"  Days Remaining: {cert_details.get('days_remaining')}")
            if ssl_info.get('warnings'):
                report_lines.append("  SSL Warnings:")
                for warn in ssl_info['warnings']:
                    report_lines.append(f"    - {warn}")
        else:
            report_lines.append(f"  SSL/TLS Analysis Status: {ssl_info.get('status', 'N/A')}")
            if ssl_info.get('errors'):
                report_lines.append("  SSL Errors:")
                for err in ssl_info['errors']:
                    report_lines.append(f"    - {err}")

        report_lines.append("\n--- Fuzzing Results ---")
        if scan_results.get("fuzzing_results"):
            for fuzz_res in scan_results["fuzzing_results"]:
                report_lines.append(f"- [VULNERABLE] {fuzz_res.get('payload_type').upper()} at {fuzz_res.get('url')}")
                report_lines.append(f"  Parameter: {fuzz_res.get('param')}")
                report_lines.append(f"  Payload: {fuzz_res.get('payload')}")
                report_lines.append(f"  Details: {', '.join(fuzz_res.get('details', []))}")
        else:
            report_lines.append("No fuzzing vulnerabilities detected.")

        report_lines.append("\n--- End of Report ---")
        return "\n".join(report_lines)

    def _generate_html_report(self, scan_results: Dict[str, Any]) -> str:
        """Generates an HTML report using a Jinja2 template."""
        template = self.env.get_template("base.html")
        return template.render(
            scan_results=scan_results,
            report_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            urlparse=urlparse # Make urlparse available in template
        )

    def generate_report(self, scan_results: Dict[str, Any], output_format: str, output_file: str):
        """
        Generates and saves the report based on the specified format.

        Args:
            scan_results (Dict[str, Any]): The complete scan results dictionary.
            output_format (str): The desired output format (html, json, text).
            output_file (str): The path to save the report file.
        """
        self.logger.info(f"Generating report in {output_format} format to {output_file}")

        report_content = ""
        if output_format == "json":
            report_content = self._format_json_report(scan_results)
        elif output_format == "text":
            report_content = self._format_text_report(scan_results)
        elif output_format == "html":
            report_content = self._generate_html_report(scan_results)
        else:
            self.logger.error(f"Unsupported report format: {output_format}")
            return

        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(report_content)
            self.logger.info(f"Report successfully saved to: {output_file}")
        except IOError as e:
            self.logger.error(f"Error saving report to {output_file}: {e}")

# Example Usage (for testing purposes)
async def main_reporter_test():
    class MockArgs:
        def __init__(self, verbose=True, output_format="html", output_file="test_report.html"):
            self.verbose = verbose
            self.output_format = output_format
            self.output_file = output_file

    mock_args = MockArgs(verbose=True)
    reporter = Reporter(mock_args)

    # Mock scan results (similar to what reconx.py would provide)
    mock_scan_results = {
        "target": "https://example.com",
        "status": "Completed",
        "technologies": {
            "WordPress": {"version": "6.0.0", "source": "generator_meta"},
            "Nginx": {"source": "header"}
        },
        "endpoints": [
            "https://example.com/",
            "https://example.com/about",
            "https://example.com/wp-admin/"
        ],
        "subdomains": [
            "https://www.example.com",
            "https://blog.example.com"
        ],
        "ports": {
            "93.184.216.34": [{"port": 80, "status": "open"}, {"port": 443, "status": "open"}]
        },
        "vulnerabilities": [
            {
                "technology": "WordPress",
                "version": "6.0.0",
                "vulnerability": {
                    "cve": ["CVE-2022-XXXX"],
                    "description": "Authenticated Stored XSS in WordPress Core",
                    "severity": "Medium",
                    "exploit_link": "https://example.com/exploit/wp-xss"
                }
            },
            {
                "technology": "Apache",
                "version": "2.4.49",
                "vulnerability": {
                    "cve": ["CVE-2021-41773"],
                    "description": "Apache HTTP Server Path Traversal and RCE",
                    "severity": "Critical",
                    "exploit_link": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"
                }
            }
        ],
        "ssl_info": {
            "host": "example.com",
            "port": 443,
            "status": "Success",
            "certificate_details": {
                "subject": {"commonName": "example.com"},
                "issuer": {"commonName": "Let's Encrypt"},
                "not_before": "Jan 1 00:00:00 2024 GMT",
                "not_after": "Apr 1 00:00:00 2024 GMT",
                "valid": True,
                "expiry_status": "Valid",
                "days_remaining": 60,
                "alt_names": ["example.com", "www.example.com"]
            },
            "tls_versions": ["TLSv1.3"],
            "cipher_suites": [{"name": "TLS_AES_256_GCM_SHA384", "tls_version": "TLSv1.3", "bits": 256}],
            "warnings": [],
            "errors": []
        },
        "headers_info": {
            "target_url": "https://example.com",
            "headers_present": {
                "strict-transport-security": "max-age=31536000",
                "x-content-type-options": "nosniff",
                "content-security-policy": "default-src 'self';"
            },
            "missing_headers": [
                {"header": "X-Frame-Options", "description": "Prevents clickjacking.", "severity": "Medium"}
            ],
            "insecure_headers": [
                {"header": "Strict-Transport-Security", "value": "max-age=31536000", "issue": "Missing includeSubDomains", "expected": "max-age=31536000; includeSubDomains; preload", "severity": "High"}
            ],
            "content_security_policy": {"present": True, "policy": "default-src 'self';", "issues": ["CSP is missing 'default-src' directive, which is crucial for defining a fallback policy."]},
            "cors_status": "Not Present",
            "warnings": ["CORS 'Access-Control-Allow-Origin' is set to '*', allowing all origins."],
            "errors": []
        },
        "fuzzing_results": [
            {
                "url": "https://example.com/search?q=test",
                "param": "q",
                "payload_type": "xss",
                "payload": "<script>alert(1)</script>",
                "status_code": 200,
                "response_time": 0.5,
                "vulnerable": True,
                "details": ["XSS payload '<script>alert(1)</script>' reflected in response."]
            }
        ]
    }

    print("\n--- Generating HTML Report ---")
    reporter.generate_report(mock_scan_results, "html", "test_report.html")

    print("\n--- Generating JSON Report ---")
    reporter.generate_report(mock_scan_results, "json", "test_report.json")

    print("\n--- Generating Text Report ---")
    reporter.generate_report(mock_scan_results, "text", "test_report.txt")

    print("\nReports generated: test_report.html, test_report.json, test_report.txt")

if __name__ == "__main__":
    import sys
    # asyncio.run(main_reporter_test()) # This needs an event loop, but reporter itself is not async
    print("Run `python -m asyncio -c 'import asyncio; from reports.reporter import main_reporter_test; asyncio.run(main_reporter_test())'` to test the reporter.")
    print("Or, run `python reconx.py -u <your_url> -o report.html` once fully integrated.")

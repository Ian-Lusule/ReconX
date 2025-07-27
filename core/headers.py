import logging
import httpx
from typing import Dict, Any, List
from core.utils import setup_logging # Assuming setup_logging is in utils

class HeaderAnalyzer:
    """
    Analyzes HTTP security headers of a target URL to identify missing or insecure configurations.
    """
    def __init__(self, args, client: httpx.AsyncClient): # Added client parameter
        """
        Initializes the HeaderAnalyzer.

        Args:
            args (argparse.Namespace): Command-line arguments.
            client (httpx.AsyncClient): An initialized httpx.AsyncClient instance.
        """
        self.args = args
        self.client = client # Store the shared httpx client
        setup_logging(args.verbose)
        self.logger = logging.getLogger(__name__)
        self.logger.info("HeaderAnalyzer initialized.")

        # List of recommended security headers and their ideal values/presence
        self.recommended_headers = {
            "Strict-Transport-Security": {"present": True, "min_age": 31536000}, # 1 year
            "Content-Security-Policy": {"present": True, "details_check": True},
            "X-Content-Type-Options": {"present": True, "value": "nosniff"},
            "X-Frame-Options": {"present": True, "value_options": ["DENY", "SAMEORIGIN"]},
            "X-XSS-Protection": {"present": True, "value": "1; mode=block"},
            "Referrer-Policy": {"present": True, "value_options": ["no-referrer", "no-referrer-when-downgrade", "same-origin", "strict-origin", "strict-origin-when-cross-origin"]},
            "Permissions-Policy": {"present": True, "details_check": True}, # Formerly Feature-Policy
            "Cross-Origin-Opener-Policy": {"present": True, "value_options": ["same-origin", "same-origin-allow-popups", "unsafe-none"]},
            "Cross-Origin-Embedder-Policy": {"present": True, "value_options": ["require-corp", "credentialless", "unsafe-none"]},
            "Cross-Origin-Resource-Policy": {"present": True, "value_options": ["same-origin", "same-site", "cross-origin"]}
        }

    async def analyze(self, url: str) -> Dict[str, Any]:
        """
        Analyzes HTTP security headers for the given URL.

        Args:
            url (str): The target URL.

        Returns:
            Dict[str, Any]: A dictionary containing header analysis results.
        """
        self.logger.info(f"Starting header analysis for: {url}")
        header_info = {
            "target_url": url,
            "status": "Failed",
            "all_headers": {},
            "missing_headers": [],
            "insecure_headers": [],
            "content_security_policy": {"present": False, "issues": [], "policy": None}
        }

        try:
            response = await self.client.head(url, follow_redirects=True) # Use HEAD for efficiency
            response.raise_for_status()

            header_info["status"] = "Success"
            header_info["all_headers"] = {k.lower(): v for k, v in response.headers.items()}

            # Check for missing headers
            for header_name, config in self.recommended_headers.items():
                if config["present"] and header_name.lower() not in header_info["all_headers"]:
                    header_info["missing_headers"].append(header_name)
                    self.logger.warning(f"  [MISSING] Header: {header_name}")

            # Check for insecure configurations
            for header_name, config in self.recommended_headers.items():
                if header_name.lower() in header_info["all_headers"]:
                    actual_value = header_info["all_headers"][header_name.lower()]

                    if header_name == "Strict-Transport-Security":
                        if "max-age" not in actual_value.lower() or int(re.search(r"max-age=(\d+)", actual_value).group(1)) < config["min_age"]:
                            header_info["insecure_headers"].append(f"{header_name} (max-age too low or missing)")
                            self.logger.warning(f"  [INSECURE] HSTS max-age too low: {actual_value}")
                        if "includeSubDomains" not in actual_value.lower():
                             header_info["warnings"].append(f"{header_name} does not include subdomains.")
                             self.logger.warning(f"  [WARNING] HSTS does not include subdomains: {actual_value}")

                    elif header_name == "Content-Security-Policy":
                        header_info["content_security_policy"]["present"] = True
                        header_info["content_security_policy"]["policy"] = actual_value
                        csp_issues = self._analyze_csp(actual_value)
                        if csp_issues:
                            header_info["content_security_policy"]["issues"].extend(csp_issues)
                            header_info["insecure_headers"].append(f"{header_name} (misconfigured)")
                            self.logger.warning(f"  [INSECURE] CSP issues: {csp_issues}")

                    elif "value" in config and actual_value.lower() != config["value"].lower():
                        header_info["insecure_headers"].append(f"{header_name} (incorrect value: '{actual_value}', expected: '{config['value']}')")
                        self.logger.warning(f"  [INSECURE] Header {header_name} has incorrect value: {actual_value}")

                    elif "value_options" in config and actual_value.lower() not in [v.lower() for v in config["value_options"]]:
                        header_info["insecure_headers"].append(f"{header_name} (unrecommended value: '{actual_value}', expected one of: {', '.join(config['value_options'])})")
                        self.logger.warning(f"  [INSECURE] Header {header_name} has unrecommended value: {actual_value}")

            self.logger.info(f"Header analysis completed for {url}. Missing: {len(header_info['missing_headers'])}, Insecure: {len(header_info['insecure_headers'])}")

        except httpx.RequestError as exc:
            header_info["errors"].append(f"Request error: {exc}")
            self.logger.error(f"Header analysis request error for {url}: {exc}")
        except httpx.HTTPStatusError as exc:
            header_info["errors"].append(f"HTTP error {exc.response.status_code}: {exc.response.text}")
            self.logger.error(f"Header analysis HTTP error for {url}: {exc.response.status_code}")
        except Exception as e:
            header_info["errors"].append(f"An unexpected error occurred: {e}")
            self.logger.error(f"An unexpected error occurred during header analysis for {url}: {e}")

        return header_info

    def _analyze_csp(self, csp_policy: str) -> List[str]:
        """
        Analyzes a Content-Security-Policy string for common weaknesses.
        This is a simplified analysis and can be greatly expanded.
        """
        issues = []
        policy_directives = {d.split(' ')[0].strip(): ' '.join(d.split(' ')[1:]).strip() for d in csp_policy.split(';') if d.strip()}

        # Check for 'unsafe-inline' or 'unsafe-eval'
        for directive, value in policy_directives.items():
            if "'unsafe-inline'" in value.lower() or "unsafe-inline" in value.lower():
                issues.append(f"'{directive}' allows 'unsafe-inline' scripts/styles.")
            if "'unsafe-eval'" in value.lower() or "unsafe-eval" in value.lower():
                issues.append(f"'{directive}' allows 'unsafe-eval' for scripts.")

        # Check for missing default-src or script-src/object-src
        if "default-src" not in policy_directives and ("script-src" not in policy_directives or "object-src" not in policy_directives):
            issues.append("Missing 'default-src' or specific 'script-src'/'object-src' directives.")

        # Check for wildcard sources (might be too permissive)
        for directive, value in policy_directives.items():
            if "'*'" in value or "http:" in value or "https:" in value:
                # Be more specific: check if it's just '*' or if it's a specific domain followed by '*'
                # This is a heuristic, a true CSP parser is complex.
                if value.strip() == "*" or value.strip() == "'*'" or "data:" in value:
                    issues.append(f"'{directive}' is too permissive (allows '*') or includes 'data:' URIs.")

        # Check for missing 'object-src' if 'default-src' is not restrictive
        if "object-src" not in policy_directives and policy_directives.get("default-src", "").strip() != "'none'":
            issues.append("Missing 'object-src' directive, potentially allowing Flash/Java applets.")

        # Check for missing 'base-uri'
        if "base-uri" not in policy_directives:
            issues.append("Missing 'base-uri' directive, potentially vulnerable to base tag injection.")

        return issues

# Example Usage (for testing purposes)
async def main_header_analyzer_test():
    class MockArgs:
        def __init__(self, verbose=True):
            self.verbose = verbose

    mock_args = MockArgs(verbose=True)

    # Create a shared client for testing
    test_client = httpx.AsyncClient(timeout=10, follow_redirects=True)

    analyzer = HeaderAnalyzer(mock_args, client=test_client)

    print("\n--- Header Analyzer Test: Good Headers ---")
    # Simulate a response with good security headers
    class MockResponseGoodHeaders:
        def __init__(self):
            self.status_code = 200
            self.headers = {
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "X-XSS-Protection": "1; mode=block",
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "geolocation=(), camera=()",
                "Cross-Origin-Opener-Policy": "same-origin",
                "Cross-Origin-Embedder-Policy": "require-corp",
                "Cross-Origin-Resource-Policy": "same-origin"
            }
        def raise_for_status(self): pass

    # Simulate a response with missing/insecure headers
    class MockResponseBadHeaders:
        def __init__(self):
            self.status_code = 200
            self.headers = {
                "Server": "Apache", # Non-security header
                "X-Frame-Options": "ALLOWALL", # Insecure value
                "Content-Security-Policy": "script-src 'unsafe-inline'; default-src *;" # Insecure CSP
            }
        def raise_for_status(self): pass

    # Patch the client.head method for testing
    original_head = test_client.head

    async def mock_head_good(url, **kwargs):
        return MockResponseGoodHeaders()
    test_client.head = mock_head_good
    results_good = await analyzer.analyze("https://good-headers.com")
    print(f"Header Analysis Results (Good Headers): {results_good}")

    async def mock_head_bad(url, **kwargs):
        return MockResponseBadHeaders()
    test_client.head = mock_head_bad
    results_bad = await analyzer.analyze("https://bad-headers.com")
    print(f"\n--- Header Analyzer Test: Bad Headers ---")
    print(f"Header Analysis Results (Bad Headers): {results_bad}")

    # Restore original client.head
    test_client.head = original_head

    await test_client.aclose() # Close the shared client

if __name__ == "__main__":
    import sys
    # asyncio.run(main_header_analyzer_test())
    print("This module is designed to be integrated into ReconX. Run `python reconx.py -u <your_url>` to test the full flow.")

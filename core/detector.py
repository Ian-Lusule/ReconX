import logging
import httpx
import re
from typing import Dict, Any, List
from core.utils import setup_logging, fetch_url # Assuming fetch_url is in utils

class Detector:
    """
    Detects technologies, CMS, frameworks, and their versions based on various indicators
    like HTTP headers, HTML meta tags, script paths, and known fingerprints.
    """
    def __init__(self, args, client: httpx.AsyncClient, fingerprints: Dict[str, Any]):
        """
        Initializes the Detector.

        Args:
            args (argparse.Namespace): Command-line arguments.
            client (httpx.AsyncClient): An initialized httpx.AsyncClient instance.
            fingerprints (Dict[str, Any]): A dictionary of technology fingerprints.
        """
        self.args = args
        self.client = client # Store the shared httpx client
        self.fingerprints = fingerprints
        setup_logging(args.verbose)
        self.logger = logging.getLogger(__name__)
        self.logger.info("Detector initialized.")

    async def fingerprint(self, url: str) -> Dict[str, Dict[str, str]]:
        """
        Attempts to fingerprint technologies on the given URL.

        Args:
            url (str): The target URL.

        Returns:
            Dict[str, Dict[str, str]]: A dictionary of detected technologies and their details.
                                       e.g., {"WordPress": {"version": "6.0", "method": "meta_tag"}}
        """
        self.logger.info(f"Starting technology fingerprinting for: {url}")
        detected_technologies = {}

        response = await fetch_url(url, client=self.client)
        if not response:
            self.logger.error(f"Could not fetch URL {url} for fingerprinting.")
            return detected_technologies

        headers = response.headers
        html_content = response.text

        for tech_name, tech_info in self.fingerprints.items():
            version = "N/A"
            method = "N/A"

            # 1. Check Headers
            if "headers" in tech_info:
                for header_name, header_value_regex in tech_info["headers"].items():
                    if header_name.lower() in headers:
                        if re.search(header_value_regex, headers[header_name.lower()], re.IGNORECASE):
                            detected_technologies[tech_name] = {"version": version, "method": f"header_{header_name}"}
                            self.logger.debug(f"  [Header Match] {tech_name} detected via header '{header_name}'.")
                            break # Move to next technology once detected by a header

            # 2. Check HTML Keywords
            if "html_keywords" in tech_info and html_content:
                for keyword in tech_info["html_keywords"]:
                    if keyword in html_content:
                        detected_technologies[tech_name] = {"version": version, "method": "html_keyword"}
                        self.logger.debug(f"  [HTML Keyword Match] {tech_name} detected via HTML keyword '{keyword}'.")
                        break

            # 3. Check HTML Meta Tags (for version)
            if "version_regex" in tech_info and html_content:
                match = re.search(tech_info["version_regex"], html_content)
                if match:
                    version = match.group(1) if len(match.groups()) > 0 else "Detected"
                    detected_technologies[tech_name] = {"version": version, "method": "meta_tag"}
                    self.logger.debug(f"  [Meta Tag Match] {tech_name} detected with version {version} via meta tag.")

            # 4. Check Script/Link Paths (simple existence check)
            if "paths" in tech_info:
                for path in tech_info["paths"]:
                    full_path = f"{url.rstrip('/')}{path}"
                    path_response = await self.client.head(full_path, follow_redirects=True) # Use HEAD for efficiency
                    if path_response.status_code == 200:
                        detected_technologies[tech_name] = {"version": version, "method": "path_existence"}
                        self.logger.debug(f"  [Path Existence] {tech_name} detected via path '{path}'.")
                        break

            # 5. Check JS Regex (for client-side frameworks)
            if "js_regex" in tech_info and html_content:
                for js_pattern in tech_info["js_regex"]:
                    if re.search(js_pattern, html_content):
                        detected_technologies[tech_name] = {"version": version, "method": "js_regex"}
                        self.logger.debug(f"  [JS Regex Match] {tech_name} detected via JS regex '{js_pattern}'.")
                        break

            # 6. Check Cookies
            if "cookies" in tech_info and response.cookies:
                for cookie_name in tech_info["cookies"]:
                    if cookie_name in response.cookies:
                        detected_technologies[tech_name] = {"version": version, "method": "cookie"}
                        self.logger.debug(f"  [Cookie Match] {tech_name} detected via cookie '{cookie_name}'.")
                        break

        self.logger.info("Technology fingerprinting completed.")
        return detected_technologies

# Example Usage (for testing purposes)
async def main_detector_test():
    class MockArgs:
        def __init__(self, verbose=True):
            self.verbose = verbose

    mock_args = MockArgs(verbose=True)

    # Create a shared client for testing
    test_client = httpx.AsyncClient(timeout=10, follow_redirects=True)

    # Sample fingerprints (a subset for testing)
    sample_fingerprints = {
        "WordPress": {
            "version_regex": "<meta name=\"generator\" content=\"WordPress ([\\d.]+)\"",
            "paths": ["/wp-admin/", "/wp-login.php"],
            "html_keywords": ["wp-content"]
        },
        "Nginx": {
            "headers": {"server": "nginx"}
        },
        "React": {
            "html_keywords": ["<div id=\"root\">"],
            "js_regex": ["React\\.createElement"]
        }
    }

    detector = Detector(mock_args, client=test_client, fingerprints=sample_fingerprints)

    print("\n--- Detector Test: WordPress Site (simulated) ---")
    # You would typically fetch a real WordPress site or mock its response
    # For this test, we'll simulate a response that matches WordPress
    class MockResponse:
        def __init__(self, status_code, headers, text, url):
            self.status_code = status_code
            self._headers = headers
            self._text = text
            self._url = url
            self.cookies = {} # Add cookies attribute

        @property
        def headers(self):
            return self._headers

        @property
        def text(self):
            return self._text

        @property
        def url(self):
            return self._url

        def raise_for_status(self):
            if self.status_code >= 400:
                raise httpx.HTTPStatusError(f"HTTP Error {self.status_code}", request=httpx.Request("GET", str(self.url)), response=self)

    # Mock fetch_url to return a WordPress-like response
    async def mock_fetch_url(url, client):
        if "wordpress.org" in url:
            return MockResponse(
                200,
                {"server": "nginx"},
                '<html><head><meta name="generator" content="WordPress 6.0"></head><body><div id="wp-content"></div></body></html>',
                url
            )
        elif "react.dev" in url:
            return MockResponse(
                200,
                {"server": "cloudflare"},
                '<html><body><div id="root"></div><script>React.createElement("div")</script></body></html>',
                url
            )
        return MockResponse(200, {}, "<html><body>Hello World</body></html>", url)

    # Temporarily patch fetch_url for this test
    original_fetch_url = globals()['fetch_url']
    globals()['fetch_url'] = mock_fetch_url

    detected = await detector.fingerprint("https://example-wordpress.org")
    print(f"Detected technologies for WordPress site: {detected}")

    print("\n--- Detector Test: React Site (simulated) ---")
    detected_react = await detector.fingerprint("https://example-react.dev")
    print(f"Detected technologies for React site: {detected_react}")

    print("\n--- Detector Test: Generic Site ---")
    detected_generic = await detector.fingerprint("https://example.com")
    print(f"Detected technologies for generic site: {detected_generic}")

    # Restore original fetch_url
    globals()['fetch_url'] = original_fetch_url

    await test_client.aclose() # Close the shared client

if __name__ == "__main__":
    import sys
    # asyncio.run(main_detector_test())
    print("This module is designed to be integrated into ReconX. Run `python reconx.py -u <your_url>` to test the full flow.")

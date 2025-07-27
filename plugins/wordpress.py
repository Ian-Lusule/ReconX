import logging
import httpx
import re
from typing import Dict, Any, List
from core.utils import setup_logging, fetch_url # Assuming fetch_url is in utils

class WordPressPlugin:
    """
    Plugin for detecting WordPress installations and checking for common
    WordPress-specific vulnerabilities or misconfigurations.
    """
    def __init__(self, args, client: httpx.AsyncClient):
        """
        Initializes the WordPressPlugin.

        Args:
            args (argparse.Namespace): Command-line arguments.
            client (httpx.AsyncClient): An initialized httpx.AsyncClient instance.
        """
        self.args = args
        self.client = client # Store the shared httpx client
        setup_logging(args.verbose)
        self.logger = logging.getLogger(__name__)
        self.logger.info("WordPressPlugin initialized.")

        self.wordpress_indicators = {
            "meta_generator_regex": r"<meta name=\"generator\" content=\"WordPress ([\\d.]+)\"",
            "paths": ["/wp-admin/", "/wp-login.php", "/wp-content/", "/wp-includes/"],
            "cookies": ["wordpress_test_cookie"],
            "html_keywords": ["wp-content", "wp-includes", "WordPress"]
        }
        self.common_wp_vuln_paths = [
            "/wp-content/plugins/revslider/readme.html", # Example of a known vulnerable plugin path
            "/wp-admin/admin-ajax.php?action=revslider_ajax_action&client_action=get_template_html" # Example of a vulnerable endpoint
        ]

    async def detect(self, url: str) -> Dict[str, Any] | None:
        """
        Detects if the target URL is running WordPress and tries to determine its version.

        Args:
            url (str): The target URL.

        Returns:
            Dict[str, Any] | None: Dictionary with detection status and version if found, else None.
        """
        self.logger.info(f"Detecting WordPress on: {url}")

        response = await fetch_url(url, client=self.client)
        if not response:
            self.logger.debug(f"Failed to fetch {url} for WordPress detection.")
            return None

        html_content = response.text
        headers = response.headers

        detected = False
        version = "N/A"
        detection_method = []

        # Check meta generator tag for version
        match = re.search(self.wordpress_indicators["meta_generator_regex"], html_content)
        if match:
            version = match.group(1)
            detected = True
            detection_method.append("meta_generator_tag")
            self.logger.debug(f"  [WP Detected] via meta generator tag, version: {version}")

        # Check common paths
        for path in self.wordpress_indicators["paths"]:
            full_path = f"{url.rstrip('/')}{path}"
            try:
                head_response = await self.client.head(full_path, follow_redirects=True, timeout=5)
                if head_response.status_code == 200:
                    detected = True
                    detection_method.append(f"path_existence:{path}")
                    self.logger.debug(f"  [WP Detected] via path existence: {full_path}")
            except httpx.RequestError:
                pass # Ignore connection errors for paths

        # Check HTML keywords
        for keyword in self.wordpress_indicators["html_keywords"]:
            if keyword in html_content:
                detected = True
                detection_method.append(f"html_keyword:{keyword}")
                self.logger.debug(f"  [WP Detected] via HTML keyword: {keyword}")
                break

        # Check for WordPress specific cookies
        for cookie_name in self.wordpress_indicators["cookies"]:
            if cookie_name in response.cookies:
                detected = True
                detection_method.append(f"cookie:{cookie_name}")
                self.logger.debug(f"  [WP Detected] via cookie: {cookie_name}")
                break

        if detected:
            self.logger.info(f"WordPress detected on {url} (Version: {version}). Methods: {', '.join(detection_method)}")
            return {"detected": True, "version": version, "methods": detection_method}
        else:
            self.logger.info(f"WordPress not detected on: {url}")
            return {"detected": False}

    async def run_specific_checks(self, url: str, detected_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Runs WordPress-specific vulnerability checks.

        Args:
            url (str): The target URL.
            detected_info (Dict[str, Any]): Information about the detected WordPress instance.

        Returns:
            List[Dict[str, Any]]: A list of identified WordPress vulnerabilities.
        """
        self.logger.info(f"Running WordPress-specific checks for: {url}")
        vulnerabilities = []
        wp_version = detected_info.get("version", "N/A")

        # Example: Check for common vulnerable paths (highly simplified)
        for vuln_path in self.common_wp_vuln_paths:
            full_vuln_url = f"{url.rstrip('/')}{vuln_path}"
            try:
                response = await self.client.get(full_vuln_url, follow_redirects=True, timeout=10)
                if response.status_code == 200 and "vulnerability" in response.text.lower(): # Simple content check
                    vulnerabilities.append({
                        "name": "Known WordPress Vulnerable Path/File",
                        "description": f"Potentially vulnerable file/path found: {full_vuln_url}",
                        "severity": "Medium",
                        "reference": full_vuln_url
                    })
                    self.logger.warning(f"  [VULN] Found known vulnerable WordPress path: {full_vuln_url}")
            except httpx.RequestError:
                pass # Ignore connection errors

        # Example: Check for outdated WordPress core (requires version comparison logic)
        if wp_version != "N/A":
            # This would ideally integrate with a CVE database or a list of known vulnerable WP versions
            # For demonstration, a very basic check
            if wp_version.startswith("4.") or wp_version.startswith("5.0"): # Example: Old versions
                vulnerabilities.append({
                    "name": "Outdated WordPress Core",
                    "description": f"WordPress version {wp_version} is potentially outdated and may contain known vulnerabilities.",
                    "severity": "High",
                    "reference": "Check official WordPress security advisories."
                })
                self.logger.warning(f"  [VULN] Outdated WordPress core detected: {wp_version}")

        # Add more specific checks here (e.g., enumeration of users, exposed debug info)

        if not vulnerabilities:
            self.logger.info(f"No specific WordPress vulnerabilities found for {url}.")
        return vulnerabilities

# Example Usage (for testing purposes)
async def main_wordpress_plugin_test():
    class MockArgs:
        def __init__(self, verbose=True):
            self.verbose = verbose

    mock_args = MockArgs(verbose=True)

    # Create a shared client for testing
    test_client = httpx.AsyncClient(timeout=10, follow_redirects=True)

    plugin = WordPressPlugin(mock_args, client=test_client)

    print("\n--- WordPress Plugin Test: Detection ---")
    # Mock fetch_url to simulate a WordPress site
    async def mock_fetch_url_wp(url, client):
        class MockResponse:
            def __init__(self, status_code, text, headers=None, cookies=None):
                self.status_code = status_code
                self._text = text
                self.headers = headers if headers else {}
                self.cookies = cookies if cookies else {}
            @property
            def text(self): return self._text
            def raise_for_status(self): pass # Simplified for mock

        if "wp-login.php" in url:
            return MockResponse(200, "<html><body>WordPress Login</body></html>")
        elif "wp-content" in url:
            return MockResponse(200, "/* WP content */")
        elif "revslider" in url: # For vuln path check
            return MockResponse(200, "<h1>Revolution Slider Vulnerability</h1>")
        return MockResponse(200, '<html><head><meta name="generator" content="WordPress 5.8"></head><body><div id="wp-content"></div></body></html>', cookies={"wordpress_test_cookie": "WP Cookie"})

    original_fetch_url = globals()['fetch_url']
    globals()['fetch_url'] = mock_fetch_url_wp
    original_client_head = test_client.head
    original_client_get = test_client.get

    async def mock_client_head(url, **kwargs):
        if "/wp-admin/" in url or "/wp-login.php" in url:
            return httpx.Response(200, request=httpx.Request("HEAD", url))
        return httpx.Response(404, request=httpx.Request("HEAD", url))

    async def mock_client_get(url, **kwargs):
        return await mock_fetch_url_wp(url, test_client)

    test_client.head = mock_client_head
    test_client.get = mock_client_get

    detected_info = await plugin.detect("https://example-wp.com")
    print(f"Detection Results: {detected_info}")

    if detected_info and detected_info.get("detected"):
        print("\n--- WordPress Plugin Test: Specific Checks ---")
        vulnerabilities = await plugin.run_specific_checks("https://example-wp.com", detected_info)
        if vulnerabilities:
            print("Identified WordPress Vulnerabilities:")
            for vuln in vulnerabilities:
                print(f"- {vuln.get('name')}: {vuln.get('description')} (Severity: {vuln.get('severity')})")
        else:
            print("No specific WordPress vulnerabilities found.")

    # Restore original functions/methods
    globals()['fetch_url'] = original_fetch_url
    test_client.head = original_client_head
    test_client.get = original_client_get

    await test_client.aclose() # Close the shared client

if __name__ == "__main__":
    import sys
    # asyncio.run(main_wordpress_plugin_test())
    print("This module is designed to be integrated into ReconX.")

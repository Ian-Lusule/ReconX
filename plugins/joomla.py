import logging
import httpx
import re
from typing import Dict, Any, List
from core.utils import setup_logging, fetch_url

class JoomlaPlugin:
    """
    Plugin for detecting Joomla installations and checking for common
    Joomla-specific vulnerabilities or misconfigurations.
    """
    def __init__(self, args, client: httpx.AsyncClient):
        """
        Initializes the JoomlaPlugin.

        Args:
            args (argparse.Namespace): Command-line arguments.
            client (httpx.AsyncClient): An initialized httpx.AsyncClient instance.
        """
        self.args = args
        self.client = client # Store the shared httpx client
        setup_logging(args.verbose)
        self.logger = logging.getLogger(__name__)
        self.logger.info("JoomlaPlugin initialized.")

        self.joomla_indicators = {
            "meta_generator_regex": r"<meta name=\"generator\" content=\"Joomla! ([\\d.]+)\"",
            "paths": ["/administrator/", "/media/system/js/core.js", "/templates/"],
            "html_keywords": ["Joomla!", "joomla.debug"]
        }
        self.common_joomla_vuln_paths = [
            "/components/com_media/views/media/tmpl/default.php", # Example of a known vulnerable path
            "/index.php?option=com_users&view=reset" # Password reset vulnerability example
        ]

    async def detect(self, url: str) -> Dict[str, Any] | None:
        """
        Detects if the target URL is running Joomla and tries to determine its version.

        Args:
            url (str): The target URL.

        Returns:
            Dict[str, Any] | None: Dictionary with detection status and version if found, else None.
        """
        self.logger.info(f"Detecting Joomla on: {url}")

        response = await fetch_url(url, client=self.client)
        if not response:
            self.logger.debug(f"Failed to fetch {url} for Joomla detection.")
            return None

        html_content = response.text

        detected = False
        version = "N/A"
        detection_method = []

        # Check meta generator tag for version
        match = re.search(self.joomla_indicators["meta_generator_regex"], html_content)
        if match:
            version = match.group(1)
            detected = True
            detection_method.append("meta_generator_tag")
            self.logger.debug(f"  [Joomla Detected] via meta generator tag, version: {version}")

        # Check common paths
        for path in self.joomla_indicators["paths"]:
            full_path = f"{url.rstrip('/')}{path}"
            try:
                head_response = await self.client.head(full_path, follow_redirects=True, timeout=5)
                if head_response.status_code == 200:
                    detected = True
                    detection_method.append(f"path_existence:{path}")
                    self.logger.debug(f"  [Joomla Detected] via path existence: {full_path}")
            except httpx.RequestError:
                pass

        # Check HTML keywords
        for keyword in self.joomla_indicators["html_keywords"]:
            if keyword in html_content:
                detected = True
                detection_method.append(f"html_keyword:{keyword}")
                self.logger.debug(f"  [Joomla Detected] via HTML keyword: {keyword}")
                break

        if detected:
            self.logger.info(f"Joomla detected on {url} (Version: {version}). Methods: {', '.join(detection_method)}")
            return {"detected": True, "version": version, "methods": detection_method}
        else:
            self.logger.info(f"Joomla not detected on: {url}")
            return {"detected": False}

    async def run_specific_checks(self, url: str, detected_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Runs Joomla-specific vulnerability checks.

        Args:
            url (str): The target URL.
            detected_info (Dict[str, Any]): Information about the detected Joomla instance.

        Returns:
            List[Dict[str, Any]]: A list of identified Joomla vulnerabilities.
        """
        self.logger.info(f"Running Joomla-specific checks for: {url}")
        vulnerabilities = []
        joomla_version = detected_info.get("version", "N/A")

        # Example: Check for common vulnerable paths
        for vuln_path in self.common_joomla_vuln_paths:
            full_vuln_url = f"{url.rstrip('/')}{vuln_path}"
            try:
                response = await self.client.get(full_vuln_url, follow_redirects=True, timeout=10)
                if response.status_code == 200 and ("error" not in response.text.lower() and "not found" not in response.text.lower()):
                    vulnerabilities.append({
                        "name": "Known Joomla Vulnerable Path/File",
                        "description": f"Potentially vulnerable file/path found: {full_vuln_url}",
                        "severity": "Medium",
                        "reference": full_vuln_url
                    })
                    self.logger.warning(f"  [VULN] Found known vulnerable Joomla path: {full_vuln_url}")
            except httpx.RequestError:
                pass

        # Example: Check for outdated Joomla core
        if joomla_version != "N/A":
            if joomla_version.startswith("3.") or joomla_version.startswith("2."): # Example: Old versions
                vulnerabilities.append({
                    "name": "Outdated Joomla Core",
                    "description": f"Joomla version {joomla_version} is potentially outdated and may contain known vulnerabilities.",
                    "severity": "High",
                    "reference": "Check official Joomla security advisories."
                })
                self.logger.warning(f"  [VULN] Outdated Joomla core detected: {joomla_version}")

        if not vulnerabilities:
            self.logger.info(f"No specific Joomla vulnerabilities found for {url}.")
        return vulnerabilities

# Example Usage (for testing purposes)
async def main_joomla_plugin_test():
    class MockArgs:
        def __init__(self, verbose=True):
            self.verbose = verbose

    mock_args = MockArgs(verbose=True)
    test_client = httpx.AsyncClient(timeout=10, follow_redirects=True)
    plugin = JoomlaPlugin(mock_args, client=test_client)

    async def mock_fetch_url_joomla(url, client):
        class MockResponse:
            def __init__(self, status_code, text, headers=None):
                self.status_code = status_code
                self._text = text
                self.headers = headers if headers else {}
            @property
            def text(self): return self._text
            def raise_for_status(self): pass

        if "/administrator/" in url:
            return MockResponse(200, "<html><body>Joomla Administrator Login</body></html>")
        elif "core.js" in url:
            return MockResponse(200, "/* Joomla core JS */")
        return MockResponse(200, '<html><head><meta name="generator" content="Joomla! 3.9.27"></head><body>Joomla site</body></html>')

    original_fetch_url = globals()['fetch_url']
    globals()['fetch_url'] = mock_fetch_url_joomla
    original_client_head = test_client.head
    original_client_get = test_client.get

    async def mock_client_head(url, **kwargs):
        if "/administrator/" in url or "/media/system/js/core.js" in url:
            return httpx.Response(200, request=httpx.Request("HEAD", url))
        return httpx.Response(404, request=httpx.Request("HEAD", url))

    async def mock_client_get(url, **kwargs):
        return await mock_fetch_url_joomla(url, test_client)

    test_client.head = mock_client_head
    test_client.get = mock_client_get

    detected_info = await plugin.detect("https://example-joomla.com")
    print(f"Detection Results: {detected_info}")

    if detected_info and detected_info.get("detected"):
        vulnerabilities = await plugin.run_specific_checks("https://example-joomla.com", detected_info)
        if vulnerabilities:
            print("Identified Joomla Vulnerabilities:")
            for vuln in vulnerabilities:
                print(f"- {vuln.get('name')}: {vuln.get('description')} (Severity: {vuln.get('severity')})")
        else:
            print("No specific Joomla vulnerabilities found.")

    globals()['fetch_url'] = original_fetch_url
    test_client.head = original_client_head
    test_client.get = original_client_get
    await test_client.aclose()

if __name__ == "__main__":
    import sys
    # asyncio.run(main_joomla_plugin_test())
    print("This module is designed to be integrated into ReconX.")

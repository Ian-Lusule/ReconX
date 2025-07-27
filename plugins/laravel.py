import logging
import httpx
import re
from typing import Dict, Any, List
from core.utils import setup_logging, fetch_url

class LaravelPlugin:
    """
    Plugin for detecting Laravel installations and checking for common
    Laravel-specific vulnerabilities or misconfigurations.
    """
    def __init__(self, args, client: httpx.AsyncClient):
        """
        Initializes the LaravelPlugin.

        Args:
            args (argparse.Namespace): Command-line arguments.
            client (httpx.AsyncClient): An initialized httpx.AsyncClient instance.
        """
        self.args = args
        self.client = client # Store the shared httpx client
        setup_logging(args.verbose)
        self.logger = logging.getLogger(__name__)
        self.logger.info("LaravelPlugin initialized.")

        self.laravel_indicators = {
            "meta_csrf_regex": r"<meta name=\"csrf-token\" content=\"([a-zA-Z0-9]+)\">",
            "paths": ["/.env", "/vendor/", "/storage/logs/laravel.log"],
            "html_keywords": ["Laravel", "csrf_token", "mix.js"]
        }
        self.common_laravel_vuln_paths = [
            "/.env", # Exposure of environment variables
            "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" # PHPUnit RCE
        ]

    async def detect(self, url: str) -> Dict[str, Any] | None:
        """
        Detects if the target URL is running Laravel and tries to determine its version.

        Args:
            url (str): The target URL.

        Returns:
            Dict[str, Any] | None: Dictionary with detection status and version if found, else None.
        """
        self.logger.info(f"Detecting Laravel on: {url}")

        response = await fetch_url(url, client=self.client)
        if not response:
            self.logger.debug(f"Failed to fetch {url} for Laravel detection.")
            return None

        html_content = response.text

        detected = False
        version = "N/A" # Laravel version detection is harder without specific headers/files
        detection_method = []

        # Check meta CSRF token
        match = re.search(self.laravel_indicators["meta_csrf_regex"], html_content)
        if match:
            detected = True
            detection_method.append("meta_csrf_token")
            self.logger.debug(f"  [Laravel Detected] via meta CSRF token.")

        # Check common paths
        for path in self.laravel_indicators["paths"]:
            full_path = f"{url.rstrip('/')}{path}"
            try:
                head_response = await self.client.head(full_path, follow_redirects=True, timeout=5)
                if head_response.status_code == 200:
                    detected = True
                    detection_method.append(f"path_existence:{path}")
                    self.logger.debug(f"  [Laravel Detected] via path existence: {full_path}")
            except httpx.RequestError:
                pass

        # Check HTML keywords
        for keyword in self.laravel_indicators["html_keywords"]:
            if keyword in html_content:
                detected = True
                detection_method.append(f"html_keyword:{keyword}")
                self.logger.debug(f"  [Laravel Detected] via HTML keyword: {keyword}")
                break

        # A more robust Laravel version detection would involve checking specific JS files or error pages.
        # For now, we'll mark version as N/A unless a specific indicator is added.

        if detected:
            self.logger.info(f"Laravel detected on {url} (Version: {version}). Methods: {', '.join(detection_method)}")
            return {"detected": True, "version": version, "methods": detection_method}
        else:
            self.logger.info(f"Laravel not detected on: {url}")
            return {"detected": False}

    async def run_specific_checks(self, url: str, detected_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Runs Laravel-specific vulnerability checks.

        Args:
            url (str): The target URL.
            detected_info (Dict[str, Any]): Information about the detected Laravel instance.

        Returns:
            List[Dict[str, Any]]: A list of identified Laravel vulnerabilities.
        """
        self.logger.info(f"Running Laravel-specific checks for: {url}")
        vulnerabilities = []

        # Check for common vulnerable paths (e.g., exposed .env file)
        for vuln_path in self.common_laravel_vuln_paths:
            full_vuln_url = f"{url.rstrip('/')}{vuln_path}"
            try:
                response = await self.client.get(full_vuln_url, follow_redirects=True, timeout=10)
                if response.status_code == 200 and ("APP_KEY" in response.text or "DB_USERNAME" in response.text):
                    vulnerabilities.append({
                        "name": "Exposed Laravel .env file",
                        "description": f"The .env configuration file is exposed at {full_vuln_url}, potentially leaking sensitive information.",
                        "severity": "Critical",
                        "reference": "https://laravel.com/docs/master/installation#environment-configuration"
                    })
                    self.logger.warning(f"  [VULN] Exposed Laravel .env file: {full_vuln_url}")
                elif response.status_code == 200 and "PHPUnit" in response.text and "eval-stdin.php" in vuln_path:
                     vulnerabilities.append({
                        "name": "Laravel PHPUnit Remote Code Execution",
                        "description": f"PHPUnit eval-stdin.php endpoint found at {full_vuln_url}, potentially allowing RCE.",
                        "severity": "Critical",
                        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2017-9841"
                    })
                     self.logger.warning(f"  [VULN] PHPUnit RCE endpoint found: {full_vuln_url}")
            except httpx.RequestError:
                pass

        # Add more specific Laravel checks here (e.g., debug mode enabled, exposed routes)

        if not vulnerabilities:
            self.logger.info(f"No specific Laravel vulnerabilities found for {url}.")
        return vulnerabilities

# Example Usage (for testing purposes)
async def main_laravel_plugin_test():
    class MockArgs:
        def __init__(self, verbose=True):
            self.verbose = verbose

    mock_args = MockArgs(verbose=True)
    test_client = httpx.AsyncClient(timeout=10, follow_redirects=True)
    plugin = LaravelPlugin(mock_args, client=test_client)

    async def mock_fetch_url_laravel(url, client):
        class MockResponse:
            def __init__(self, status_code, text, headers=None):
                self.status_code = status_code
                self._text = text
                self.headers = headers if headers else {}
            @property
            def text(self): return self._text
            def raise_for_status(self): pass

        if ".env" in url:
            return MockResponse(200, "APP_KEY=some_secret_key\nDB_USERNAME=root")
        elif "eval-stdin.php" in url:
            return MockResponse(200, "PHPUnit version 7.x")
        return MockResponse(200, '<html><head><meta name="csrf-token" content="abc123def456"></head><body><div id="app">Laravel App</div></body></html>')

    original_fetch_url = globals()['fetch_url']
    globals()['fetch_url'] = mock_fetch_url_laravel
    original_client_head = test_client.head
    original_client_get = test_client.get

    async def mock_client_head(url, **kwargs):
        if "/.env" in url or "/vendor/" in url:
            return httpx.Response(200, request=httpx.Request("HEAD", url))
        return httpx.Response(404, request=httpx.Request("HEAD", url))

    async def mock_client_get(url, **kwargs):
        return await mock_fetch_url_laravel(url, test_client)

    test_client.head = mock_client_head
    test_client.get = mock_client_get

    detected_info = await plugin.detect("https://example-laravel.com")
    print(f"Detection Results: {detected_info}")

    if detected_info and detected_info.get("detected"):
        vulnerabilities = await plugin.run_specific_checks("https://example-laravel.com", detected_info)
        if vulnerabilities:
            print("Identified Laravel Vulnerabilities:")
            for vuln in vulnerabilities:
                print(f"- {vuln.get('name')}: {vuln.get('description')} (Severity: {vuln.get('severity')})")
        else:
            print("No specific Laravel vulnerabilities found.")

    globals()['fetch_url'] = original_fetch_url
    test_client.head = original_client_head
    test_client.get = original_client_get
    await test_client.aclose()

if __name__ == "__main__":
    import sys
    # asyncio.run(main_laravel_plugin_test())
    print("This module is designed to be integrated into ReconX.")

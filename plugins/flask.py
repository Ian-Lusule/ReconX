import logging
import httpx
import re
from typing import Dict, Any, List
from core.utils import setup_logging, fetch_url

class FlaskPlugin:
    """
    Plugin for detecting Flask applications and checking for common
    Flask-specific vulnerabilities or misconfigurations.
    """
    def __init__(self, args, client: httpx.AsyncClient):
        """
        Initializes the FlaskPlugin.

        Args:
            args (argparse.Namespace): Command-line arguments.
            client (httpx.AsyncClient): An initialized httpx.AsyncClient instance.
        """
        self.args = args
        self.client = client # Store the shared httpx client
        setup_logging(args.verbose)
        self.logger = logging.getLogger(__name__)
        self.logger.info("FlaskPlugin initialized.")

        self.flask_indicators = {
            "headers": {"server": "Werkzeug"}, # Werkzeug is the WSGI toolkit Flask uses by default
            "html_keywords": ["Debugger active!", "jinja2", "Flask"],
            "cookies": ["session"] # Flask's default session cookie name
        }
        self.common_flask_vuln_paths = [
            "/debugger", # Flask debug console
            "/console" # Another common debug/admin path
        ]

    async def detect(self, url: str) -> Dict[str, Any] | None:
        """
        Detects if the target URL is running Flask.

        Args:
            url (str): The target URL.

        Returns:
            Dict[str, Any] | None: Dictionary with detection status if found, else None.
        """
        self.logger.info(f"Detecting Flask on: {url}")

        response = await fetch_url(url, client=self.client)
        if not response:
            self.logger.debug(f"Failed to fetch {url} for Flask detection.")
            return None

        html_content = response.text
        headers = response.headers

        detected = False
        detection_method = []

        # Check headers
        if "server" in headers and "werkzeug" in headers["server"].lower():
            detected = True
            detection_method.append("header:Werkzeug")
            self.logger.debug(f"  [Flask Detected] via Server header: {headers['server']}")

        # Check HTML keywords
        for keyword in self.flask_indicators["html_keywords"]:
            if keyword in html_content:
                detected = True
                detection_method.append(f"html_keyword:{keyword}")
                self.logger.debug(f"  [Flask Detected] via HTML keyword: {keyword}")
                break

        # Check cookies
        for cookie_name in self.flask_indicators["cookies"]:
            if cookie_name in response.cookies:
                detected = True
                detection_method.append(f"cookie:{cookie_name}")
                self.logger.debug(f"  [Flask Detected] via cookie: {cookie_name}")
                break

        if detected:
            self.logger.info(f"Flask detected on {url}. Methods: {', '.join(detection_method)}")
            return {"detected": True, "version": "N/A", "methods": detection_method} # Flask doesn't have a standard version in headers/meta
        else:
            self.logger.info(f"Flask not detected on: {url}")
            return {"detected": False}

    async def run_specific_checks(self, url: str, detected_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Runs Flask-specific vulnerability checks.

        Args:
            url (str): The target URL.
            detected_info (Dict[str, Any]): Information about the detected Flask instance.

        Returns:
            List[Dict[str, Any]]: A list of identified Flask vulnerabilities.
        """
        self.logger.info(f"Running Flask-specific checks for: {url}")
        vulnerabilities = []

        # Check for exposed debug console
        for vuln_path in self.common_flask_vuln_paths:
            full_vuln_url = f"{url.rstrip('/')}{vuln_path}"
            try:
                response = await self.client.get(full_vuln_url, follow_redirects=True, timeout=10)
                if response.status_code == 200 and "Werkzeug debugger" in response.text:
                    vulnerabilities.append({
                        "name": "Exposed Flask Debugger",
                        "description": f"The Flask Werkzeug debugger is exposed at {full_vuln_url}, which can lead to remote code execution.",
                        "severity": "Critical",
                        "reference": "https://werkzeug.palletsprojects.com/en/2.0.x/debug/"
                    })
                    self.logger.warning(f"  [VULN] Exposed Flask Debugger found: {full_vuln_url}")
            except httpx.RequestError:
                pass

        # Add more specific Flask checks here (e.g., insecure session management, SSRF if applicable)

        if not vulnerabilities:
            self.logger.info(f"No specific Flask vulnerabilities found for {url}.")
        return vulnerabilities

# Example Usage (for testing purposes)
async def main_flask_plugin_test():
    class MockArgs:
        def __init__(self, verbose=True):
            self.verbose = verbose

    mock_args = MockArgs(verbose=True)
    test_client = httpx.AsyncClient(timeout=10, follow_redirects=True)
    plugin = FlaskPlugin(mock_args, client=test_client)

    async def mock_fetch_url_flask(url, client):
        class MockResponse:
            def __init__(self, status_code, text, headers=None, cookies=None):
                self.status_code = status_code
                self._text = text
                self.headers = headers if headers else {}
                self.cookies = cookies if cookies else {}
            @property
            def text(self): return self._text
            def raise_for_status(self): pass

        if "/debugger" in url:
            return MockResponse(200, "<html><body><h1>Werkzeug debugger</h1></body></html>")
        return MockResponse(200, '<html><body>Flask App</body></html>', headers={"Server": "Werkzeug/2.0.0 Python/3.9"}, cookies={"session": "abc123def456"})

    original_fetch_url = globals()['fetch_url']
    globals()['fetch_url'] = mock_fetch_url_flask
    original_client_get = test_client.get

    async def mock_client_get(url, **kwargs):
        return await mock_fetch_url_flask(url, test_client)

    test_client.get = mock_client_get

    detected_info = await plugin.detect("https://example-flask.com")
    print(f"Detection Results: {detected_info}")

    if detected_info and detected_info.get("detected"):
        vulnerabilities = await plugin.run_specific_checks("https://example-flask.com", detected_info)
        if vulnerabilities:
            print("Identified Flask Vulnerabilities:")
            for vuln in vulnerabilities:
                print(f"- {vuln.get('name')}: {vuln.get('description')} (Severity: {vuln.get('severity')})")
        else:
            print("No specific Flask vulnerabilities found.")

    globals()['fetch_url'] = original_fetch_url
    test_client.get = original_client_get
    await test_client.aclose()

if __name__ == "__main__":
    import sys
    # asyncio.run(main_flask_plugin_test())
    print("This module is designed to be integrated into ReconX.")

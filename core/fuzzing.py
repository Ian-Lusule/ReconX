import logging
import asyncio
import httpx
from urllib.parse import urlparse, urlencode, parse_qs
from typing import List, Dict, Any
from core.utils import setup_logging, fetch_url # Assuming fetch_url is in utils

class FuzzingEngine:
    """
    Performs basic fuzzing for common web vulnerabilities like XSS, SQLi, LFI, RCE, and Open Redirect.
    It injects payloads into URL parameters and form data, then analyzes responses.
    """
    def __init__(self, args, client: httpx.AsyncClient, payloads: Dict[str, List[str]]):
        """
        Initializes the FuzzingEngine.

        Args:
            args (argparse.Namespace): Command-line arguments.
            client (httpx.AsyncClient): An initialized httpx.AsyncClient instance.
            payloads (Dict[str, List[str]]): A dictionary of vulnerability types to lists of payloads.
        """
        self.args = args
        self.client = client # Store the shared httpx client
        self.payloads = payloads
        setup_logging(args.verbose)
        self.logger = logging.getLogger(__name__)
        self.logger.info("FuzzingEngine initialized.")

        # Define indicators for successful exploitation (simplified)
        self.indicators = {
            "xss": ["<script>alert", "alert(", "prompt(", "confirm("],
            "sqli": ["SQL syntax", "mysql_fetch_array", "Warning: mysql", "syntax error", "unclosed quotation mark"],
            "lfi": ["root:x:", "windows", "boot.ini", "etc/passwd"],
            "rce": ["uid=", "exec(", "system(", "cmd="],
            "open_redirect": ["Location: http", "Location: /", "Redirecting to:"] # Check for redirect headers/meta
        }

    async def _test_payload(self, method: str, url: str, param: str, payload: str, payload_type: str) -> Dict[str, Any] | None:
        """
        Tests a single payload against a URL parameter.

        Args:
            method (str): HTTP method ('GET' or 'POST').
            url (str): The base URL.
            param (str): The parameter name to inject the payload into.
            payload (str): The payload string.
            payload_type (str): The type of vulnerability being tested (e.g., "xss").

        Returns:
            Dict[str, Any] | None: Fuzzing result if a potential vulnerability is found, None otherwise.
        """
        fuzzed_url = url
        fuzzed_data = {}
        response = None

        try:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)

            if method.upper() == 'GET':
                query_params[param] = [payload] # Update or add the parameter with payload
                fuzzed_query = urlencode(query_params, doseq=True)
                fuzzed_url = parsed_url._replace(query=fuzzed_query).geturl()
                self.logger.debug(f"Testing GET: {fuzzed_url}")
                response = await self.client.get(fuzzed_url, follow_redirects=True, timeout=10)
            elif method.upper() == 'POST':
                # For POST, assume original URL is the target, and payload goes into form data
                # This is a simplification; real-world fuzzing needs to handle JSON, XML, etc.
                fuzzed_data = {param: payload}
                self.logger.debug(f"Testing POST: {url} with data: {fuzzed_data}")
                response = await self.client.post(url, data=fuzzed_data, follow_redirects=True, timeout=10)
            else:
                self.logger.warning(f"Unsupported HTTP method for fuzzing: {method}")
                return None

            if response and response.status_code < 400: # Check for successful response
                # Analyze response for indicators
                for indicator in self.indicators.get(payload_type, []):
                    if indicator.lower() in response.text.lower():
                        self.logger.warning(f"  [VULN DETECTED] {payload_type.upper()} via '{payload}' at {url} (Param: {param}) - Indicator: '{indicator}'")
                        return {
                            "url": url,
                            "method": method,
                            "param": param,
                            "payload": payload,
                            "payload_type": payload_type,
                            "status_code": response.status_code,
                            "indicator_matched": indicator,
                            "details": [f"Potential {payload_type.upper()} detected. Matched indicator: '{indicator}' in response body."]
                        }
                    # Special check for Open Redirect in headers
                    if payload_type == "open_redirect" and "location" in response.headers:
                        redirect_location = response.headers["location"]
                        if indicator.lower() in redirect_location.lower():
                            self.logger.warning(f"  [VULN DETECTED] {payload_type.upper()} via '{payload}' at {url} (Param: {param}) - Redirect: '{redirect_location}'")
                            return {
                                "url": url,
                                "method": method,
                                "param": param,
                                "payload": payload,
                                "payload_type": payload_type,
                                "status_code": response.status_code,
                                "indicator_matched": indicator,
                                "details": [f"Potential {payload_type.upper()} detected. Redirected to: '{redirect_location}'."]
                            }

        except httpx.RequestError as exc:
            self.logger.debug(f"  Fuzzing request error for {url} (param: {param}, payload: {payload}): {exc}")
        except Exception as e:
            self.logger.debug(f"  Unexpected error during fuzzing {url} (param: {param}, payload: {payload}): {e}")
        return None

    async def fuzz(self, endpoints: List[str]) -> List[Dict[str, Any]]:
        """
        Executes fuzzing against a list of discovered endpoints.

        Args:
            endpoints (List[str]): A list of URLs (endpoints) to fuzz.

        Returns:
            List[Dict[str, Any]]: A list of dictionaries, each representing a potential vulnerability found.
        """
        if not self.payloads:
            self.logger.warning("No fuzzing payloads loaded. Fuzzing skipped.")
            return []

        self.logger.info(f"Starting fuzzing for {len(endpoints)} endpoints with {len(self.payloads)} payload types.")
        fuzzing_results = []
        tasks = []

        for url in endpoints:
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)

            # Fuzz GET parameters
            for param in query_params:
                for payload_type, payloads_list in self.payloads.items():
                    for payload in payloads_list:
                        tasks.append(self._test_payload('GET', url, param, payload, payload_type))

            # Basic POST fuzzing (assuming common form parameters)
            # This part is highly simplified. A real fuzzer would discover form fields.
            common_post_params = ["id", "name", "email", "search", "query", "data", "input"]
            for param in common_post_params:
                for payload_type, payloads_list in self.payloads.items():
                    for payload in payloads_list:
                        # Only test POST if the URL is likely to accept POST data (e.g., not just an image)
                        if not url.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.css', '.js')):
                            tasks.append(self._test_payload('POST', url, param, payload, payload_type))

        results = await asyncio.gather(*tasks)

        for result in results:
            if result:
                fuzzing_results.append(result)

        self.logger.info(f"Fuzzing completed. Found {len(fuzzing_results)} potential vulnerabilities.")
        return fuzzing_results

# Example Usage (for testing purposes)
async def main_fuzzing_engine_test():
    class MockArgs:
        def __init__(self, verbose=True):
            self.verbose = verbose

    mock_args = MockArgs(verbose=True)

    # Create a shared client for testing
    test_client = httpx.AsyncClient(timeout=10, follow_redirects=True)

    sample_payloads = {
        "xss": ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>"],
        "sqli": ["' OR 1=1--", "' UNION SELECT 1,2,3--"],
        "lfi": ["../../../../etc/passwd"],
        "rce": [";id", "|whoami"],
        "open_redirect": ["https://evil.com"]
    }

    fuzzer = FuzzingEngine(mock_args, client=test_client, payloads=sample_payloads)

    print("\n--- Fuzzing Engine Test ---")

    # Mock httpx client responses for testing
    async def mock_get_post(url, **kwargs):
        class MockResponse:
            def __init__(self, status_code, text, headers=None):
                self.status_code = status_code
                self._text = text
                self.headers = headers if headers else {}
            @property
            def text(self): return self._text
            def raise_for_status(self):
                if self.status_code >= 400:
                    raise httpx.HTTPStatusError(f"HTTP Error {self.status_code}", request=httpx.Request("GET", str(url)), response=self)

        if "<script>alert(1)</script>" in url:
            return MockResponse(200, "<html><body><script>alert(1)</script></body></html>")
        elif "' OR 1=1--" in url or "' OR 1=1--" in str(kwargs.get('data')):
            return MockResponse(200, "SQL syntax error near 'OR 1=1--'")
        elif "https://evil.com" in url:
            return MockResponse(302, "", headers={"Location": "https://evil.com"})
        elif "etc/passwd" in url:
            return MockResponse(200, "root:x:0:0:root:/root:/bin/bash")
        return MockResponse(200, "Normal response")

    original_get = test_client.get
    original_post = test_client.post
    test_client.get = mock_get_post
    test_client.post = mock_get_post # Use same mock for post for simplicity

    endpoints_to_fuzz = [
        "http://test.com/search?q=test",
        "http://test.com/login", # For POST testing
        "http://test.com/redirect?url=safe.com"
    ]

    results = await fuzzer.fuzz(endpoints_to_fuzz)

    print("\nFuzzing Results:")
    if results:
        for res in results:
            print(f"- Type: {res['payload_type'].upper()}, URL: {res['url']}, Param: {res['param']}, Payload: {res['payload']}, Indicator: {res.get('indicator_matched', 'N/A')}")
    else:
        print("No vulnerabilities found during fuzzing.")

    # Restore original client methods
    test_client.get = original_get
    test_client.post = original_post

    await test_client.aclose() # Close the shared client

if __name__ == "__main__":
    import sys
    # asyncio.run(main_fuzzing_engine_test())
    print("This module is designed to be integrated into ReconX. Run `python reconx.py -u <your_url> --fuzz` to test the full flow.")

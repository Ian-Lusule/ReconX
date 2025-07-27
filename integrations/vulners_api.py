import logging
import httpx
from typing import Dict, List, Any
from core.utils import setup_logging # Assuming core.utils is available for logging setup

class VulnersAPI:
    """
    Integrates with the Vulners.com API to fetch vulnerability information
    based on detected software, versions, and CVE IDs.
    """
    def __init__(self, args=None, client: httpx.AsyncClient = None): # Added client parameter
        """
        Initializes the VulnersAPI client.
        Args:
            args (argparse.Namespace, optional): Command-line arguments.
                                                 Used for verbose logging.
            client (httpx.AsyncClient, optional): An existing httpx.AsyncClient instance.
                                                  If None, a new one is created.
        """
        self.api_base_url = "https://vulners.com/api/v3/burp/software/" # Example endpoint
        self._client = client # Store the provided client
        self._own_client = None # To manage client created by this class if none provided

        if self._client is None:
            self._own_client = httpx.AsyncClient(timeout=15) # Increased timeout for external API calls
            self._client = self._own_client

        setup_logging(args.verbose if args else False) # Set up logging
        self.logger = logging.getLogger(__name__)

        # API key management (placeholder)
        # In a real scenario, this would be loaded from a config file or env variable
        # self.api_key = os.getenv("VULNERS_API_KEY")
        # if not self.api_key:
        #     self.logger.warning("VULNERS_API_KEY not found. Vulners API calls might be rate-limited or fail.")

    async def search_software(self, software_name: str, version: str = None) -> List[Dict[str, Any]]:
        """
        Searches Vulners for vulnerabilities related to a specific software and version.

        Args:
            software_name (str): The name of the software (e.g., "WordPress", "Nginx").
            version (str, optional): The version of the software.

        Returns:
            List[Dict[str, Any]]: A list of vulnerability records found.
        """
        self.logger.info(f"Searching Vulners for {software_name} version {version or 'any'}")
        vulnerabilities = []
        try:
            params = {"software": software_name}
            if version:
                params["version"] = version
            # Add API key if available
            # if self.api_key:
            #     params["api_key"] = self.api_key

            response = await self._client.get(self.api_base_url, params=params) # Use self._client
            response.raise_for_status() # Raise an exception for HTTP errors

            data = response.json()
            if data and data.get("result") == "OK":
                for vuln_doc in data.get("data", {}).get("vulnerabilities", []):
                    # Extract relevant information
                    vuln_info = {
                        "id": vuln_doc.get("id"),
                        "title": vuln_doc.get("title"),
                        "description": vuln_doc.get("description"),
                        "severity": vuln_doc.get("cvss", {}).get("score", "N/A"), # Using CVSS score as severity
                        "published": vuln_doc.get("published"),
                        "references": vuln_doc.get("references", []),
                        "type": vuln_doc.get("type"),
                        "cvss_vector": vuln_doc.get("cvss", {}).get("vector"),
                        "cve": vuln_doc.get("cve", []) # List of CVE IDs
                    }
                    vulnerabilities.append(vuln_info)
                self.logger.info(f"Found {len(vulnerabilities)} vulnerabilities for {software_name} {version or ''} on Vulners.")
            else:
                self.logger.warning(f"Vulners API returned an error or no data for {software_name} {version or ''}: {data.get('result')}")

        except httpx.RequestError as exc:
            self.logger.error(f"Vulners API request error for {software_name} {version or ''}: {exc}")
        except httpx.HTTPStatusError as exc:
            self.logger.error(f"Vulners API HTTP error for {software_name} {version or ''} - Status {exc.response.status_code}: {exc.response.text}")
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during Vulners API search: {e}")

        return vulnerabilities

    async def search_cve(self, cve_id: str) -> List[Dict[str, Any]]:
        """
        Searches Vulners for a specific CVE ID.

        Args:
            cve_id (str): The CVE ID to search for (e.g., "CVE-2021-44228").

        Returns:
            List[Dict[str, Any]]: A list of vulnerability records related to the CVE.
        """
        self.logger.info(f"Searching Vulners for CVE ID: {cve_id}")
        vulnerabilities = []
        try:
            params = {"id": cve_id}
            # if self.api_key:
            #     params["api_key"] = self.api_key

            # Note: Vulners API might have different endpoints for CVE search vs software search.
            # This example uses the same base URL, which might need adjustment based on actual Vulners API docs.
            response = await self._client.get(self.api_base_url, params=params) # Use self._client
            response.raise_for_status()

            data = response.json()
            if data and data.get("result") == "OK":
                for vuln_doc in data.get("data", {}).get("vulnerabilities", []):
                    vuln_info = {
                        "id": vuln_doc.get("id"),
                        "title": vuln_doc.get("title"),
                        "description": vuln_doc.get("description"),
                        "severity": vuln_doc.get("cvss", {}).get("score", "N/A"),
                        "published": vuln_doc.get("published"),
                        "references": vuln_doc.get("references", []),
                        "type": vuln_doc.get("type"),
                        "cvss_vector": vuln_doc.get("cvss", {}).get("vector"),
                        "cve": vuln_doc.get("cve", [])
                    }
                    vulnerabilities.append(vuln_info)
                self.logger.info(f"Found {len(vulnerabilities)} vulnerabilities for CVE {cve_id} on Vulners.")
            else:
                self.logger.warning(f"Vulners API returned an error or no data for CVE {cve_id}: {data.get('result')}")

        except httpx.RequestError as exc:
            self.logger.error(f"Vulners API request error for CVE {cve_id}: {exc}")
        except httpx.HTTPStatusError as exc:
            self.logger.error(f"Vulners API HTTP error for CVE {cve_id} - Status {exc.response.status_code}: {exc.response.text}")
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during Vulners API CVE search: {e}")

        return vulnerabilities

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """
        Ensures the httpx client created by this class is closed.
        The shared client is managed by ReconX.
        """
        if self._own_client:
            await self._own_client.aclose()

# Example Usage (for testing purposes)
async def main_vulners_api_test():
    class MockArgs:
        def __init__(self, verbose=True):
            self.verbose = verbose

    mock_args = MockArgs(verbose=True)
    # Create a shared client for testing
    test_client = httpx.AsyncClient(timeout=10, follow_redirects=True)
    vulners_api = VulnersAPI(mock_args, client=test_client)

    print("\n--- Vulners API Test: Search Software (WordPress 6.0) ---")
    wp_vulnerabilities = await vulners_api.search_software("WordPress", "6.0")
    if wp_vulnerabilities:
        print(f"Found {len(wp_vulnerabilities)} vulnerabilities for WordPress 6.0:")
        for i, vuln in enumerate(wp_vulnerabilities[:3]): # Print first 3 for brevity
            print(f"  {i+1}. ID: {vuln.get('id')}, Title: {vuln.get('title')}, Severity: {vuln.get('severity')}")
    else:
        print("No vulnerabilities found for WordPress 6.0 or API error.")

    print("\n--- Vulners API Test: Search CVE (CVE-2021-44228 - Log4j) ---")
    log4j_vulnerabilities = await vulners_api.search_cve("CVE-2021-44228")
    if log4j_vulnerabilities:
        print(f"Found {len(log4j_vulnerabilities)} vulnerabilities for CVE-2021-44228:")
        for i, vuln in enumerate(log4j_vulnerabilities[:3]): # Print first 3 for brevity
            print(f"  {i+1}. ID: {vuln.get('id')}, Title: {vuln.get('title')}, Severity: {vuln.get('severity')}")
    else:
        print("No vulnerabilities found for CVE-2021-44228 or API error.")

    await test_client.aclose() # Close the shared client

if __name__ == "__main__":
    import sys
    # asyncio.run(main_vulners_api_test())
    print("This module is designed to be integrated into ReconX. Run `python reconx.py` to test the full flow.")
    print("Note: Vulners API might require an API key for extensive use or specific endpoints.")

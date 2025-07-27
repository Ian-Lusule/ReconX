import logging
import asyncio
import httpx
from typing import Dict, List, Any
from core.utils import setup_logging # Assuming core.utils is available for logging setup

class WappalyzerIntegration:
    """
    Integrates with Wappalyzer for advanced technology fingerprinting.
    This module will simulate using Wappalyzer's capabilities.
    A true integration would involve using a Python wrapper for Wappalyzer's
    JavaScript library (e.g., `python-wappalyzer` package) or running it via subprocess.
    """
    def __init__(self, args=None):
        """
        Initializes the WappalyzerIntegration.
        Args:
            args (argparse.Namespace, optional): Command-line arguments.
                                                 Used for verbose logging.
        """
        self.client = httpx.AsyncClient(timeout=10, follow_redirects=True)
        setup_logging(args.verbose if args else False)
        self.logger = logging.getLogger(__name__)

        # Mock Wappalyzer detection rules (simplified)
        self.mock_wappalyzer_rules = {
            "WordPress": {
                "html": ["<meta name=\"generator\" content=\"WordPress"],
                "headers": {"x-powered-by": "WordPress"},
                "url": ["/wp-content/", "/wp-includes/"]
            },
            "Joomla": {
                "html": ["<meta name=\"generator\" content=\"Joomla!"],
                "headers": {"x-powered-by": "Joomla"},
                "url": ["/media/com_joomla/"]
            },
            "React": {
                "html": ['<div id="root">', '__REACT_DEVTOOLS_GLOBAL_HOOK__'],
                "js_regex": ['React\\.createElement', 'ReactDOM\\.render']
            },
            "Nginx": {
                "headers": {"server": "nginx"}
            },
            "Apache": {
                "headers": {"server": "apache"}
            },
            "PHP": {
                "headers": {"x-powered-by": "PHP"}
            }
        }

    async def analyze(self, url: str) -> Dict[str, Dict[str, str]]:
        """
        Analyzes a URL using Wappalyzer-like techniques to detect technologies.

        Args:
            url (str): The URL to analyze.

        Returns:
            Dict[str, Dict[str, str]]: A dictionary of detected technologies
                                       with their attributes (e.g., version).
        """
        self.logger.info(f"Running Wappalyzer-like analysis for: {url}")
        detected_technologies = {}

        try:
            response = await self.client.get(url)
            response.raise_for_status()

            html_content = response.text
            headers = {k.lower(): v for k, v in response.headers.items()}

            for tech_name, rules in self.mock_wappalyzer_rules.items():
                if tech_name in detected_technologies: # Already detected by another rule
                    continue

                # Check HTML content
                for html_pattern in rules.get("html", []):
                    if html_pattern in html_content: # Simple string match for now
                        detected_technologies[tech_name] = {"source": "html"}
                        self.logger.debug(f"  Detected {tech_name} via HTML.")
                        break

                if tech_name in detected_technologies: continue

                # Check Headers
                for header_name, header_value_pattern in rules.get("headers", {}).items():
                    if header_name in headers and header_value_pattern.lower() in headers[header_name].lower():
                        detected_technologies[tech_name] = {"source": "header"}
                        self.logger.debug(f"  Detected {tech_name} via header '{header_name}'.")
                        break

                if tech_name in detected_technologies: continue

                # Check URL patterns
                for url_pattern in rules.get("url", []):
                    if url_pattern in url:
                        detected_technologies[tech_name] = {"source": "url"}
                        self.logger.debug(f"  Detected {tech_name} via URL pattern.")
                        break

                if tech_name in detected_technologies: continue

                # For JS regex, a more advanced approach would be needed to fetch and parse JS files
                # For now, we'll just check if the HTML contains any script tags that might indicate it.
                # A real Wappalyzer would execute JS or parse AST.
                for js_regex_pattern in rules.get("js_regex", []):
                    if re.search(js_regex_pattern, html_content): # Check for JS patterns in HTML
                        detected_technologies[tech_name] = {"source": "js_in_html"}
                        self.logger.debug(f"  Detected {tech_name} via JS regex in HTML.")
                        break

        except httpx.RequestError as exc:
            self.logger.error(f"Wappalyzer analysis request error for {url}: {exc}")
        except httpx.HTTPStatusError as exc:
            self.logger.error(f"Wappalyzer analysis HTTP error for {url} - Status {exc.response.status_code}: {exc.response.text}")
        except Exception as e:
            self.logger.error(f"An unexpected error occurred during Wappalyzer analysis: {e}")

        self.logger.info(f"Finished Wappalyzer-like analysis for {url}. Detected: {list(detected_technologies.keys())}")
        return detected_technologies

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """
        Ensures the httpx client is closed when the WappalyzerIntegration instance is exited.
        """
        await self.client.aclose()

# Example Usage (for testing purposes)
async def main_wappalyzer_test():
    class MockArgs:
        def __init__(self, verbose=True):
            self.verbose = verbose

    mock_args = MockArgs(verbose=True)
    wappalyzer_integration = WappalyzerIntegration(mock_args)

    print("\n--- Wappalyzer Integration Test: WordPress ---")
    # Test with a known WordPress site (replace with a real one if possible for better results)
    wp_tech = await wappalyzer_integration.analyze("https://wordpress.com")
    print(f"Detected technologies for wordpress.com: {wp_tech}")

    print("\n--- Wappalyzer Integration Test: React ---")
    # Test with a known React site
    react_tech = await wappalyzer_integration.analyze("https://react.dev")
    print(f"Detected technologies for react.dev: {react_tech}")

    print("\n--- Wappalyzer Integration Test: Example.com (Generic) ---")
    # Test with a generic site
    generic_tech = await wappalyzer_integration.analyze("http://example.com")
    print(f"Detected technologies for example.com: {generic_tech}")

    await wappalyzer_integration.client.aclose()

if __name__ == "__main__":
    import sys
    import re # Needed for the mock JS regex
    # asyncio.run(main_wappalyzer_test())
    print("This module is designed to be integrated into ReconX. Run `python reconx.py` to test the full flow.")

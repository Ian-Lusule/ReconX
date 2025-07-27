import logging
import asyncio
import socket
from typing import List, Dict, Tuple, Any # Import Any, List, Dict, Tuple
from core.utils import setup_logging # Import setup_logging

class PortScanner:
    """
    Performs port scanning on given IP addresses or hostnames.
    This implementation uses basic socket connections for simplicity.
    For production-grade, fast scanning, tools like 'masscan' or 'naabu'
    would be integrated via subprocess calls or dedicated libraries.
    """
    def __init__(self, args):
        """
        Initializes the PortScanner.
        Args:
            args (argparse.Namespace): Command-line arguments.
        """
        self.args = args
        setup_logging(args.verbose) # Set up logging for this module
        self.logger = logging.getLogger(__name__)
        # Common ports to scan. This list can be expanded.
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
            3306, 3389, 5900, 8000, 8080, 8443
        ]
        self.timeout = 1 # seconds for socket connection

    async def _scan_port(self, host: str, port: int) -> Tuple[str, int, str]:
        """
        Attempts to connect to a specific port on a host.

        Args:
            host (str): The target hostname or IP address.
            port (int): The port number to scan.

        Returns:
            Tuple[str, int, str]: (host, port, "open" or "closed" or "filtered")
        """
        try:
            # Create a socket object
            # AF_INET for IPv4, SOCK_STREAM for TCP
            reader, writer = await asyncio.open_connection(host, port, timeout=self.timeout)
            writer.close()
            await writer.wait_closed()
            self.logger.debug(f"Port {port} on {host} is OPEN.")
            return host, port, "open"
        except (asyncio.TimeoutError, ConnectionRefusedError):
            self.logger.debug(f"Port {port} on {host} is CLOSED/FILTERED (Connection Refused/Timeout).")
            return host, port, "closed" # Or filtered if no response
        except OSError as e:
            # e.g., [Errno 113] No route to host, [Errno 111] Connection refused
            self.logger.debug(f"Port {port} on {host} is CLOSED/FILTERED (OS Error: {e}).")
            return host, port, "closed"
        except Exception as e:
            self.logger.error(f"Error scanning port {port} on {host}: {e}")
            return host, port, "error"

    async def scan(self, targets: List[str], ports: List[int] = None) -> Dict[str, List[Dict[str, Any]]]:
        """
        Scans a list of target hosts for open ports.

        Args:
            targets (List[str]): A list of hostnames or IP addresses to scan.
            ports (List[int], optional): A list of specific ports to scan.
                                         Defaults to self.common_ports if None.

        Returns:
            Dict[str, List[Dict[str, Any]]]: A dictionary where keys are target hosts
                                             and values are lists of open ports with status.
                                             e.g., {"example.com": [{"port": 80, "status": "open"}]}
        """
        if ports is None:
            ports_to_scan = self.common_ports
        else:
            ports_to_scan = ports

        self.logger.info(f"Starting port scan on {len(targets)} targets for {len(ports_to_scan)} ports each.")
        all_scan_results: Dict[str, List[Dict[str, Any]]] = {target: [] for target in targets}

        tasks = []
        for target in targets:
            for port in ports_to_scan:
                tasks.append(self._scan_port(target, port))

        results = await asyncio.gather(*tasks)

        for host, port, status in results:
            if status == "open":
                all_scan_results[host].append({"port": port, "status": status})
                self.logger.info(f"  [OPEN] {host}:{port}")
            else:
                self.logger.debug(f"  {host}:{port} is {status}")

        self.logger.info("Port scan completed.")
        return all_scan_results

# Example Usage (for testing purposes)
async def main_port_scanner_test():
    class MockArgs:
        def __init__(self, verbose=True):
            self.verbose = verbose

    mock_args = MockArgs(verbose=True)
    scanner = PortScanner(mock_args)

    # Test with a local IP (e.g., your localhost) and a non-existent IP
    targets = ["127.0.0.1", "scanme.nmap.org"] # scanme.nmap.org is a public host for testing nmap
    custom_ports = [22, 80, 443, 8080] # Test common web/ssh ports

    print("\n--- Port Scan Test ---")
    scan_results = await scanner.scan(targets, custom_ports)
    print("\nScan Results Summary:")
    for host, ports_info in scan_results.items():
        print(f"Host: {host}")
        if ports_info:
            for p_info in ports_info:
                print(f"  Port {p_info['port']}: {p_info['status']}")
        else:
            print("  No open ports found or all filtered/closed.")

if __name__ == "__main__":
    import logging
    import sys
    # asyncio.run(main_port_scanner_test())
    print("Run `python reconx.py -u <your_url> --port-scan` to test the full flow once integrated.")

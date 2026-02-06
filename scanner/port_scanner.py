import nmap
import sys
from ui.colors import Style, Fore
from config import DEFAULT_NMAP_ARGS


class PortScanner:

    def __init__(self):
        self.scanner = nmap.PortScanner()


    #scan - run nmap
    def scan(self, ip_address: str) -> list:
        #nmap arguments
        args_parts = [
            DEFAULT_NMAP_ARGS['base_scan'],
            '-sV', '--open',
            DEFAULT_NMAP_ARGS['timing'],
            DEFAULT_NMAP_ARGS['min_rate'],
            DEFAULT_NMAP_ARGS['max_retries'],
            DEFAULT_NMAP_ARGS['timeout']
        ]
        args = ' '.join(args_parts)

        print(f"\n{Style.BRIGHT}Running: nmap {args} on {ip_address}{Style.RESET_ALL}")
        print("(This may take a bit)...")

        #run nmap
        try:
            self.scanner.scan(hosts=ip_address, arguments=args)
        except Exception as e:
            print(f"Error running nmap: {e}")
            sys.exit(1)

        if ip_address not in self.scanner.all_hosts():
            return []

        return self._parse_results(ip_address)



    #output (open ports..) - returns openservecies
    def _parse_results(self, ip_address: str) -> list:
        print("\n" + "=" * 60)
        print(f"{Style.BRIGHT}{Fore.CYAN}SCAN RESULTS{Style.RESET_ALL}")
        print("=" * 60)

        header = f"{'PORT':>6}  {'STATE':>7}  {'SERVICE':<12}  {'PRODUCT':<20}  {'VERSION':<12}"
        print(Style.BRIGHT + header + Style.RESET_ALL)
        print("-" * 70)

        open_services = []
        tcp_ports = self.scanner[ip_address].get('tcp', {})

        for port, info in sorted(tcp_ports.items()):
            if info.get('state') == 'open':
                self._display_port_info(port, info)
                open_services.append((
                    port,
                    info.get('product', '') or info.get('name', ''),
                    info.get('version', '')
                ))

        return open_services


    # helper function to display 1 ports info
    def _display_port_info(self, port: int, info: dict):
        print(f"{port:>6}  "
              f"{info.get('state', 'unknown'):>7}  "
              f"{info.get('name', ''):<12}  "
              f"{info.get('product', ''):<20}  "
              f"{info.get('version', ''):<12}"
              f"{info.get('extra', ''):<20}")
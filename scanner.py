import nmap
import ipaddress
import re
import sys

port_range_pattern = re.compile(r"([0-9]+)-([0-9]+)")

port_min = 0
port_max = 65535

while True:
    ip_add_entered = input("\nPlease enter the ip address that you want to scan: ").strip()
    try:
        ip_address_obj = ipaddress.ip_address(ip_add_entered)
        print("You entered a valid ip address.")
        break
    except Exception:
        print("You entered an invalid ip address. Try again.")

while True:
    print("Please enter the range of ports you want to scan in format: <int>-<int>")
    port_range = input("Enter port range: ").strip()
    port_range_valid = port_range_pattern.search(port_range.replace(" ", ""))
    if port_range_valid:
        port_min = int(port_range_valid.group(1))
        port_max = int(port_range_valid.group(2))
        if 0 <= port_min <= 65535 and 0 <= port_max <= 65535 and port_min <= port_max:
            break
        else:
            print("Port numbers must be between 0 and 65535 and start <= end. Try again.")
    else:
        print("Invalid format")

nm = nmap.PortScanner()

ports_spec = f"{port_min}-{port_max}"
print(f"\nRunning nmap -sV on {ip_add_entered} ports {ports_spec} ... (this may take a bit)")

try:
    result = nm.scan(ip_add_entered, ports_spec, arguments='-sV')
except Exception as e:
    print(f"Error running nmap: {e}")
    sys.exit(1)

host_dict = result.get('scan', {}).get(ip_add_entered, {})
tcp_dict = host_dict.get('tcp', {})

if not tcp_dict:
    print("No TCP info returned (host down or no open ports in that range).")
    sys.exit(0)

#table output
print("\nScan results:")
print(f"{'PORT':>6}  {'STATE':>7}  {'SERVICE':<12}  {'PRODUCT':<20}  {'VERSION':<12}  {'EXTRA'}")
print("-" * 80)

for port, info in sorted(tcp_dict.items()):
    state = info.get('state', 'unknown')
    svc = info.get('name', '') or ''
    product = info.get('product', '') or ''
    version = info.get('version', '') or ''
    extra = info.get('extrainfo', '') or ''

    print(f"{port:>6}  {state:>7}  {svc:<12}  {product:<20}  {version:<12}  {extra}")


import ipaddress
import re
from ui.colors import Style, Fore


#valid ip?
def validate_ip_address(ip_str: str) -> bool:
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


#prompt user for ip @
def get_ip_input(prompt="\nPlease enter the IP address to scan: ") -> str:
    while True:
        ip_input = input(prompt).strip()
        if validate_ip_address(ip_input):
            print(f"{Fore.GREEN}Valid IP address entered.{Style.RESET_ALL}")
            return ip_input
        print(f"{Fore.RED}Invalid IP address. Please try again.{Style.RESET_ALL}")
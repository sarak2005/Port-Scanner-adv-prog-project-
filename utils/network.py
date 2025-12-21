import ipaddress
import re


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
            print("Valid IP address entered.")
            return ip_input
        print("Invalid IP address. Please try again.")
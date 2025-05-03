"""
Module for user input.

Handles user input - sanitises and validates user input, ensures a url scheme is present,
and invokes a function from another module to test if the website can be reached.

Functions:
    sanitise_address(address): removes unwanted characters and trailing slashes.
    ensure_scheme(address): adds http(s) to an address
    is_valid_address(address): validates the input
    get_address(): collects address from user
"""
#regex library
import re
#library to parse url
from urllib.parse import urlparse

def sanitise_address(address):
    """
    Sanitise entered address to remove whitespace and trailing slashes.
    Arguments:
        address - the website address entered by the use
    Returns:
        address - the sanitised version of the entered address
    """
    #removes trailing or leading whitespace
    address = address.strip()
    #removes trailing slashes
    address = re.sub(r'/*$', '', address)
    return address


def ensure_scheme(address):
    """
    Ensures the address has a scheme (http or https).
    If not, defaults to http.
    Arguments:
        address - the website address entered by the use
    Returns:
        address - the address with an appropriate scheme
    """
    #checks for a scheme, and adds http:// if none is found
    parsed = urlparse(address)
    if not parsed.scheme or not parsed.netloc:
        return f"http://{address}"
    return address



def is_valid_address(address):
    """
    Validate whether the given address is a valid IP address or domain name.
    The function uses regex to match the intput.

    Parameters:
        address(str): the address string to evaluate
    Returns:
        re.match | None: A match if the address is valid, otherwise none.
    """

    #regex to validate IP address format
    ipv4_pattern = re.compile(
        #checks for the inclusion of http(s) (optional)
        r"^(http[s]?://)?"     
        #regex pattern for IP address
        r"(\d{1,3}\.){3}\d{1,3}"
        #checks for the inclusion of a port (optional)
        r"(:\d{1,5})?$"
    )

    #regex to validate url format
    domain_pattern = re.compile(
        #checks for the inclusion of http(s) (optional)
        r"^(http[s]?://)?"
        #regex pattern for domain name
        r"([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(/[\w\-/]*)*" 
        #checks for the inclusion of a port (optional)
        r"(:\d{1,5})?$")

    return (
        ipv4_pattern.match(address)
        or domain_pattern.match(address)
    )


def get_address():
    """
    Gets the target address from the user.
    Validates and processes it through reach_address.
    Returns:
        address
        returns the address entered by the user after sanitisation and validation
    """
    address = input("Enter a website address or IP address: \n")
    sanitised = sanitise_address(address)

    #input validation
    while not is_valid_address(sanitised):
        print("Invalid address format. Please enter a valid domain or IP.")
        address = input("Enter a website address or IP address: \n")
        sanitised = sanitise_address(address)
    address = ensure_scheme(sanitised)
    return f"{address}/favicon.ico"

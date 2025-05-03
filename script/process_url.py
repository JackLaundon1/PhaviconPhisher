"""
Favicon fetching and hashing module.

This module contains functions check if an address
is reachable, and then download and hash the favicon.

Functions:
get_hash(url): Downloads the favicon and generates a mmh3
Then invokes the shodan_search function passing in the hash.

get_url(web_address): Fetches the favicon url

reach_address(web_address): Tests connection to the given web address

Dependencies:
requests: Requests library for web requests
favicon: Favicon library to get a site's favicon
mmh3: MurmurHash3 - the format used by shodan
"""

#regex
import re

#base64
import base64

#mmh3 library
import mmh3

#Requests library
import requests

def get_hash(url):
    """
    This function hashes the favicon of the provided website.
    Returns:
        mmh3 hash of the website's favicon
    """

    try:
        response = requests.get(url, timeout=10)
        #if the response code is 200 (the favicon was reached)
        if response.status_code == 200:
            #saves the favicon to a file
            with open("favicon.ico", 'wb') as file:
                file.write(response.content)

            #reads and hashes the file
            with open("favicon.ico", "rb") as file:
                #encodes the file into base 64
                b64_image = base64.b64encode(file.read())
                #gets string representation of the file by decoding it to UTF-8
                utf8_b64 = b64_image.decode('utf-8')
                #formats the string into lines every 76 characters to comply with MIME standards
                line_split = re.sub("(.{76}|$)", "\\1\n", utf8_b64, 0, re.DOTALL)
                #hashes the string representation of the favicon
                fav_hash = mmh3.hash(line_split)
                #outputs the hash
                print(f"The favicon hash is: {fav_hash}")
                return fav_hash
        else:
            print("Failed to download favicon")
    except requests.exceptions.RequestException as e:
        print(f"Could not reach favicon: {e}")


def reach_address(web_address):
    """
    Attempts to reach the given address.
    If the address is not reached withing 10 seconds, the function returns false.
    Returns:
        true if the website can be reached, false if it cannot.
    """

    try:
        response = requests.get(web_address, timeout=10)
        #returns true if the status code is 200 i.e. the website is reachable
        return response.status_code == 200
    except requests.exceptions.RequestException:
        print("Address could not be reached")
        #returns false if the website cannot be reached
        return False

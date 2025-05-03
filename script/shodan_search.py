"""
Shodan module

This module contains all the functions required 
to use the shodan API.
Functions:
search(favicon_hash): searches the hash on shodan.
"""

#OS library
import os

#Shodan API
import shodan

def search(favicon_hash):
    """Search for favicon hash on Shodan using the Shodan API.
    Calls the search_results.process_results function, passing in the results and favicon hash.
    Arguments:
        favicon_hash: mmh3 hash of website favicon
    Returns:
        results | none: returns the results variable if successful, else returns nothing.
        """
    #gets the API key from the environment variable
    shodan_api_key = os.getenv("SHODAN_API_KEY")
    api = shodan.Shodan(shodan_api_key)
    if shodan_api_key:
        try:
            #uses the Shodan search API to search for the hash
            results = api.search(f"http.favicon.hash:{favicon_hash}")
            return results
        except shodan.APIError as e:
            print(f"Error: {e}")
            return
    else:
        print("Shodan API Key not found.")
        return

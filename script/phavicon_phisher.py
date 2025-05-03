"""
Favicon Phisher - A tool used to detect phishing sites using the favicon.
This script allows the user to enter an IPv4 address or web url, optionally specifying a port.
If the website and favicon can be reached, the script hashes the favicon in murmur hash 3 format
and searches the hash on shodan.
The script will return whether or not the website is likely a phishing 
site based on various criteria such as domain characteristics, 
non-standard ports, lack of or self-signed SSL certificate, and will 
output a list of all other suspected phishing sites using this hash.

Functions:
arg_parse(): Parses command line arguments to display the usage information.
display(): Displays ASCII art and developer information.
main(): The entry point of the script.

Developed by Jack Laundon.
Github: https://github.com/JackLaundon1
"""

#argparse library
import argparse
#styling for ASCII art
from colorama import Fore, Style, init
#user input module
import user_input
#process url module
import process_url
#shodan module
import shodan_search
#search results module
import search_results
def arg_parse():
    """Parse command-line arguments.
    This function uses the argparse module to parse arguments.
    Returns:
        argparse.Namespace: The parsed arguments
    """
    #argparse use
    arg_parser = argparse.ArgumentParser(
        description="Favicon Phisher - A tool used to detect phishing sites using the favicon.",
        epilog="Usage: Enter an IPv4 address or website url, optionally specifying the port.\n" \
        "The script will return whether or not the website is likely a phishing site. \n" \
        "Developed by Jack Laundon. \n" \
        "Github: https://github.com/JackLaundon1", 
        #formats the text
        formatter_class=argparse.RawTextHelpFormatter
    )
    return arg_parser.parse_args()


def display():
    """Displays ASCII graphic to the user.
    Returns:
        none.
    
    """
    init(autoreset=True)

    #"""used to keep ascii formatting
    ascii_logo = f"""{Fore.GREEN}{Style.BRIGHT}
    ____  _                 _                 ____  _     _     _               
    |  _ \\| |__   __ ___   _(_) ___ ___  _ __ |  _ \\| |__ (_)___| |__   ___ _ __ 
    | |_) | '_ \\ / _` \\ \\ / / |/ __/ _ \\| '_ \\| |_) | '_ \\| / __| '_ \\ / _ \\ '__|
    |  __/| | | | (_| |\\ V /| | (_| (_) | | | |  __/| | | | \\__ \\ | | |  __/ |   
    |_|   |_| |_|\\__,_| \\_/ |_|\\___\\___/|_| |_|_|   |_| |_|_|___/_| |_|\\___|_|   
    {Style.RESET_ALL}
    """

    print(ascii_logo)
    print("A tool to detect phishing sites using the favicon. \n"
          "Developed by Jack Laundon. \n"
          "Github: https://github.com/JackLaundon1")


def main():
    """
    Entry point of the script.
    Calls arg_parse() to parse command line arguments.
    Then calls display() to show the ASCII art, followed by
    calling user_input.get_address() to get the web address from the user.
    Then, calls process_url.get_hash(), shodan_search.search(), search_results.process_results().
    Returns:
        nothing
    """
    try:
        # Parse the command-line arguments
        arg_parse()
        #displays the graphic and start the address retrieval process
        display()
        #calls the user_input.get_address function to handle user input
        address = user_input.get_address()
        if not process_url.reach_address(address):
            print("Website could not be reached.  Ensure you have a valid network connection")
            return
        #gets the hash of the file
        if address is None:
            print("Error: Unable to retrieve a valid address or favicon URL.")
            return
        #gets the hash of the favicon
        fav_hash = process_url.get_hash(address)
        #passes the hash into the shodan_search.search function
        results = shodan_search.search(fav_hash)
         #calls the process_results function
        search_results.process_results(results, fav_hash, address)
    #stops the program if the user interrupts
    except KeyboardInterrupt:
        print("\nInterrupted - script cancelled.")
#ensures the main function is called
if __name__ == "__main__":
    main()
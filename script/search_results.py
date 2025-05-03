"""
Results Module.  This module filters out and displays the results.
The given IP address is compared against the results, 
and a warning message is displayed if the address may be a phishing site.
The rest of the results are output to a text file.

Functions:
add_reason(ip, port, result, reason): adds an IP and reason if appropriate to the dict.
port_test(results): Tests each result from shodan for non-standard ports.
domain_test(results): Tests each result from shodan for a suspicious domain characteristics.
ssl_test(results): Tests each result from shodan for either a missing SSL 
certificate or a self-signed certificate.
process_results(results, favicon_hash): Calls other functions, 
outputting the findings to a text file and checking if 
the provided IP is flagged as a phishing site.
"""
#regex library
import re
#library to parse the url/ip addreerss
from urllib.parse import urlparse

#default dict
from collections import defaultdict

#global variable used to access variable from all functions
potential_phishing_sites = {}

def add_reason(ip, port, result, reason):
    """Adds reason for a specific IP-port combination.
    Arguments: 
        ip: the address of the website
        port: the port of the web address being tested
        result: an item in the results dict
        reason: reason for suspicion
    Returns:
        nothing
    """
    #creates an entry in the dict if the IP is not found
    if ip not in potential_phishing_sites:
        potential_phishing_sites[ip] = {}
    #if the IP is found but the port is not, adds it to the dict along with the reasons
    if port not in potential_phishing_sites[ip]:
        potential_phishing_sites[ip][port] = {
            "reasons": [reason],
            "details": result
        }
    #if the reason has not already been added, add it
    elif reason not in potential_phishing_sites[ip][port]["reasons"]:
        potential_phishing_sites[ip][port]["reasons"].append(reason)

def port_test(results):
    """Tests for non-standard ports in use by the address.
    Arguments:
        results (dict): The scan results from shodan
    Returns:
        nothing"""
    for result in results['matches']:
        ip = result.get("ip_str")
        port = int(result.get('port'))
        if port not in [80, 443]:
            add_reason(ip, port, result, "Non-standard port")

def domain_test(results):
    """
    Tests for suspicious domain characteristics.
    Characteristics are:
    suspicious TLD
    very short domain name
    many hyphens in the domain
    many sub domains
    suspicious keywords in the address.
    Arguments:
        results (dict): The scan results from shodan
    Returns:
        nothing
    """

    #list of suspicious TLDs - data from :
    # https://www.cybercrimeinfocenter.org/top-20-tlds-by-malicious-phishing-domains
    domains = [".tk", ".buzz", ".xyz", ".top", ".ga", ".ml",
               ".info", ".cf", ".gq", ".icu", ".wang", ".live", 
               ".net", ".cn", ".online", ".host", ".org", ".us", 
               ".ru", ".io"]
    for result in results['matches']:
        hostnames = result.get("hostnames", [])
        ip = result.get("ip_str")
        for hostname in hostnames:
            for domain in domains:
                #checks for suspicious TLD
                if hostname.endswith(domain):
                    add_reason(ip, result.get('port'), result, "Domain TLD is suspicious")
                    break
            #checks for a short domain name
            domain_part = hostname.split(".")[-2] if "." in hostname else hostname
            if len(domain_part) < 4:
                add_reason(ip, result.get("port"), result, "Domain name is very short")

            #checks for excessive hyphens
            if hostname.count('-') > 2:
                add_reason(ip, result.get("port"), result, "Domain contains many hyphens")

            #checks for too many subdomains
            if hostname.count('.') > 3:
                add_reason(ip, result.get("port"), result, "Domain has too many subdomains")

            #checks for suspicious keywords
            if re.search(r"(login|verify|update|secure|account|bank|paypal)", hostname):
                add_reason(ip, result.get("port"), result, "Domain name " \
                "contains suspicious keywords")




def ssl_test(results):
    """Tests for self-certified SSL certs or lack of SSL cert.
        Arguments: 
            results (dict): The scan results from shodan
        Returns:
            nothing."""
    for result in results['matches']:
        ip = result.get("ip_str")
        ssl_cert = result.get('ssl', {})
        port = int(result.get('port'))
        #if no SSL certificate is found
        if not ssl_cert:
            add_reason(ip, port, result, "No SSL certificate")
        #if the SSL cert is not empty
        elif ssl_cert != "" and ssl_cert != {}:
            #assigns variables to data from the result
            cert = ssl_cert.get('cert', {})
            issuer = cert.get('issuer', {})
            subject = cert.get('subject', {})
            #tests for self signed certificate
            if issuer == subject and issuer != {} and issuer != "":
                add_reason(ip, port, result, "Self-signed SSL certificate")
                result["ssl_subject"] = subject
                result["ssl_issuer"] = issuer


def process_results(results, favicon_hash, address):
    """
    Processes scan results, evaluates for phishing indicators, and outputs findings.
    Calls the port_test, domain_test, and ssl_test scans passing in results every time.
    Compares the given address to the results and determines if the site is likely phishing.

    Arguments:
        results (dict): The scan results from shodan
        favicon_hash (int): The mmh3 hash of the site's favicon.
    Returns:
        nothing
    """
    #empty dict for ip and port combinations
    if not results or 'matches' not in results:
        print("No valid results returned from Shodan")
        return
    ip_port_reasons = defaultdict(lambda: {
    "reasons": set(),
    "hostnames": [],
    "details": {}
    })

    port_test(results)
    domain_test(results)
    ssl_test(results)

    for ip, port_data in potential_phishing_sites.items():
        for port, data in port_data.items():
            ip_port_key = (ip, port)
            
            #automatically adds the reasons to the set and hostnames to the list
            ip_port_reasons[ip_port_key]["reasons"].update(data["reasons"])
            ip_port_reasons[ip_port_key]["hostnames"].extend(h.lower() for h in data["details"].get('hostnames', []))
            ip_port_reasons[ip_port_key]["details"] = data["details"]

    #outputs results to the text file
    with open("FaviconPhisherOutput.txt", "w", encoding="utf-8") as f:
        f.write(f"Results found for hash {favicon_hash}:\n")
        f.write("-" * 40 + "\n")

        #loops through all the unique ip and port combinations
        for (ip, port), data in ip_port_reasons.items():
            f.write(f"IP: {ip}\n")
            f.write(f"Port: {port}\n")
            f.write(f"Hostnames: {', '.join(data['hostnames']) if data['hostnames'] else 'N/A'}\n")
            f.write(f"Location: {data['details'].get('location', 'N/A')}\n")
            f.write(f"Reasons: {', '.join(data['reasons'])}\n")
            f.write("-" * 40 + "\n")

    #splits the ip and port
    parsed = urlparse(address)
    stripped_ip = parsed.hostname
    stripped_port = parsed.port if parsed.port else (443 if parsed.scheme == "https" else 80)

    #searches for the ip and port in the results and print a warning if matched
    match_found = False
    for (ip, port), data in ip_port_reasons.items():
        if ip == stripped_ip and port == stripped_port:
            match_found = True
            print("\n" + "=" * 60)
            print("WARNING: Potential Phishing Site Detected")
            print("=" * 60)
            print(f"Target IP      : {ip}")
            print(f"Target Port    : {port}")
            print("Reasons:")
            for reason in sorted(data['reasons']):
                print(f"  - {reason}")
            print("=" * 60 + "\n")
            break

    print("\n" + "-" * 60)
    print("Scan Complete")
    print("-" * 60)
    print("A list of other suspicious sites using this favicon has been \n" \
    "saved to: PhaviconPhisherOutput.txt")
    if not match_found:
        print("No flags were raised for the provided address.")
    else:
        print("The provided address has been flagged. Review details above.")
    print("Thank you for using FaviconPhisher.")
    print("-" * 60 + "\n")
    return

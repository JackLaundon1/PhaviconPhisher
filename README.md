# PhaviconPhisher

This Python script helps identify potentially phishing websites by analyzing their favicons. By calculating the hash of a favicon and querying the Shodan database, the script detects other domains using the same favicon, a common trait among phishing sites.

## How It Works

1. The script prompts the user to input a website or IP address.
2. It retrieves the site's favicon and calculates its `mmh3` hash.
3. It queries Shodan to find other hosts using the same hash.
4. It lists all matched hosts to a file (`PhaviconPhisherOutput.txt`) and informs the user if the website is likely to be a phishing site based on the results.

## Dependencies

The following dependencies are required:

- `shodan`
- `mmh3`
- `colorama`
- `requests`

They can be installed using using pip:

```bash
pip install shodan mmh3 colorama requests
```
## Docker 
The script can be run in a docker container, as a Dockerfile is included.  
1. Install Docker
2. Build a Docker container in the script directory
3. Run the container in interactive mode and pass in your own Shodan API key


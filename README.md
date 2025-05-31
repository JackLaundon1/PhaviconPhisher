# PhaviconPhisher

This Python script helps identify potentially phishing websites by analyzing their favicons. By calculating the hash of a favicon and querying the Shodan database, the script detects other domains using the same favicon, a common trait among phishing sites.

## How It Works

1. The script prompts the user to input a website or IP address.
2. It retrieves the site's favicon and calculates its `mmh3` hash.
3. It queries Shodan to find other hosts using the same hash.
4. It lists all matched hosts to a file (`PhaviconPhisherOutput.txt`) and informs the user if the website is likely to be a phishing site based on the results.

## Installation
### Requirements
A valid Shodan API key of member level or higher.  The current source code for PhaviconPhisher uses an environment variable (recommended for security) but this can be changed if desired.

### Python Installation
The following dependencies are required:

- `shodan`
- `mmh3`
- `colorama`
- `requests`

They can be installed using using pip:

```bash
pip install shodan mmh3 colorama requests
```
A valid Shodan API key must be set, in an environment variable or otherwise, or the script will not function correctly.
### Docker 
The script can be run in a docker container, as a Dockerfile is included.  
1. Install Docker
2. Build a Docker container in the script directory
3. Run the container in interactive mode and pass in your own Shodan API key

### Windows Executable 
A standalone Windows .exe file.
1. Download PhaviconPhisher.exe
2. Set your Shodan API key as an environment variable.  This can be done temporarily:
``` Temporary (Command Prompt)
set SHODAN_API_KEY=<API key> PhaviconPhisher.exe
```
Or permanently and system-wide:
```Permament (System-Wode):
1. Open Start → search Environment Variables.
2. Click "Edit the system environment variables".
3. Under User Variables, click New:
4. Name: SHODAN_API_KEY
5. Value: your actual key.
6. Save and close, then run PhaviconPhisher.exe.
```
### Cloning from GitHub
The source code can be cloned from GitHub:
```
 git clone https://github.com/JackLaundon1/PhaviconPhisher
```

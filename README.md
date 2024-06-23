# VTSearch

## VirusTotal Lookup Script

This script allows you to interact with the VirusTotal API to scan URLs and search for file hashes. It provides a summary of how many vendors have marked the given URL or file hash as malicious.
### Features

   - Scan a URL using VirusTotal.
   - Search for a file hash on VirusTotal.
   - Summarize the results indicating how many vendors have marked the input as malicious.

### Requirements

    - Python 3.x
    - requests library

### Installation
git clone https://github.com/yourusername/virustotal-lookup.git
cd virustotal-lookup

Install the required Python package:
    pip install requests

Usage
    Replace YOUR_VIRUSTOTAL_API_KEY with your actual VirusTotal API key in the script.
    Run the script:
    python virus_total_scan.py
    Follow the on-screen prompts to either scan a URL or search for a file hash.

Example
Scanning a URL

    - Select option 1 to scan a URL.
    - Enter the URL you wish to scan.
    - The script will output the number of vendors that marked the URL as malicious.

Searching for a File Hash

    - Select option 2 to search for a file hash.
    - Enter the file hash you wish to search for.
    - The script will output the number of vendors that marked the file hash as malicious.

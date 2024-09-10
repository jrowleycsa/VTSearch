import requests

def get_virus_total_hash_report(api_key, file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        # Extracting necessary information
        data = response.json().get('data', {}).get('attributes', {})
        last_analysis_stats = data.get('last_analysis_stats', {})
        malicious = last_analysis_stats.get('malicious', 0)
        total = sum(last_analysis_stats.values())
        file_name = data.get('meaningful_name', 'N/A')
        threat_labels = ", ".join(data.get('tags', [])) or 'No threat labels'
        
        # Creating report
        return (f"Hash: {file_hash}\n"
                f"File Name: {file_name}\n"
                f"Threat Labels: {threat_labels}\n"
                f"Marked malicious by {malicious}/{total} vendors.")
    elif response.status_code == 404:
        return f"Hash {file_hash} not found on VirusTotal."
    else:
        return f"Error {response.status_code}: {response.text}"

def main():
    api_key = "YOUR_VIRUSTOTAL_API_KEY"
    output_file = "virus_total_results.txt"
    
    print("Enter file hashes (one per line), and press Enter twice when done:")
    hashes = iter(input, "")  # Collects user input until an empty line is entered

    with open(output_file, "w") as f:
        for file_hash in hashes:
            report = get_virus_total_hash_report(api_key, file_hash.strip())
            print(report)  # Output to terminal
            f.write(report + "\n\n")  # Output to file
    
    print(f"Results saved to {output_file}")

if __name__ == "__main__":
    main()

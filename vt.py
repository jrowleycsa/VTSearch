import requests
import base64

def get_virus_total_hash_report(api_key, file_hash):
    base_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    
    headers = {
        "x-apikey": api_key
    }
    
    response = requests.get(base_url, headers=headers)
    
    if response.status_code == 200:
        return summarize_report(response.json(), "file hash")
    elif response.status_code == 404:
        return f"Hash {file_hash} not found on VirusTotal."
    else:
        return f"Error retrieving hash report: {response.status_code} - {response.text}"

def summarize_report(json_response, report_type):
    data = json_response.get('data', {})
    attributes = data.get('attributes', {})
    last_analysis_stats = attributes.get('last_analysis_stats', {})
    malicious_count = last_analysis_stats.get('malicious', 0)
    total_count = sum(last_analysis_stats.values())
    
    return f"This {report_type} has been marked as malicious by {malicious_count}/{total_count} vendors."

def main():
    api_key = "YOUR_VIRUSTOTAL_API_KEY"
    output_file = "virus_total_results.txt"
    
    # Prompt user to input hashes
    print("Enter file hashes (one per line), and press Enter twice when done:")

    # Collecting multiple hashes from the user
    hashes = []
    while True:
        line = input()
        if line.strip() == "":
            break
        hashes.append(line.strip())

    # Check if any hashes were provided
    if not hashes:
        print("No hashes were entered. Exiting.")
        return
    
    # Open output file to write results
    with open(output_file, "w") as f:
        for file_hash in hashes:
            report = get_virus_total_hash_report(api_key, file_hash)
            
            # Output report to the terminal
            print(f"Hash: {file_hash}")
            print(f"Report: {report}\n")
            print("="*50 + "\n")
            
            # Write the report to the file
            f.write(f"Hash: {file_hash}\n")
            f.write(f"Report: {report}\n")
            f.write("\n" + "="*50 + "\n\n")
    
    print(f"Results have been written to {output_file}")

if __name__ == "__main__":
    main()

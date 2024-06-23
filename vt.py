import requests
import base64

def get_virus_total_url_report(api_key, url):
    base_url = "https://www.virustotal.com/api/v3/urls"
    
    # Encode the URL in base64 format
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    headers = {
        "x-apikey": api_key,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    # Send the URL for scanning
    response = requests.post(base_url, headers=headers, data=f"url={url}")
    
    if response.status_code == 200:
        json_response = response.json()
        scan_id = json_response['data']['id']
        
        # Retrieve the scan report
        report_url = f"{base_url}/{url_id}"
        report_response = requests.get(report_url, headers=headers)
        
        if report_response.status_code == 200:
            return summarize_report(report_response.json(), "URL")
        else:
            return f"Error retrieving report: {report_response.status_code} - {report_response.text}"
    else:
        return f"Error scanning URL: {response.status_code} - {response.text}"

def get_virus_total_hash_report(api_key, file_hash):
    base_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    
    headers = {
        "x-apikey": api_key
    }
    
    response = requests.get(base_url, headers=headers)
    
    if response.status_code == 200:
        return summarize_report(response.json(), "file hash")
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
    
    print("VirusTotal Lookup")
    print("1. Scan a URL")
    print("2. Search for a file hash")
    choice = input("Choose an option (1 or 2): ")
    
    if choice == "1":
        url = input("Enter the URL to scan: ")
        report = get_virus_total_url_report(api_key, url)
    elif choice == "2":
        file_hash = input("Enter the file hash to search: ")
        report = get_virus_total_hash_report(api_key, file_hash)
    else:
        print("Invalid choice. Exiting.")
        return
    
    print(report)

if __name__ == "__main__":
    main()

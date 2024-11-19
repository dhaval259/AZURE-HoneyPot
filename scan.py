import requests
import json
import time

# VirusTotal API key
API_KEY = "1af7f1e7f93d08f3431100edba96ce4b69f810b7e9f64943ba543a2ddd2e01c2"  # Replace with your VirusTotal API key

# Input and output file paths
top_ip_file = "top_10_ips.txt"
output_json_file = "threat_intelligence_results.json"

# VirusTotal API URL for IP address reports
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/"

def extract_ips(file_path):
    """
    Extract IPs from the top IP file.
    Assumes the format is `<IP>: <count>` on each line.
    """
    ips = []
    try:
        with open(file_path, "r") as file:
            for line in file:
                # Extract IP before the first colon
                ip = line.split(":")[0].strip()
                if ip:  # Add only non-empty IPs
                    ips.append(ip)
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

    return ips

def fetch_vt_report(ip):
    """
    Fetch VirusTotal report for a given IP address.
    """
    headers = {"x-apikey": API_KEY}
    response = requests.get(VT_URL + ip, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to fetch data for IP {ip}. Status Code: {response.status_code}")
        return None

def analyze_ips(top_ip_file, output_json_file):
    """
    Analyze IPs from the top IP file using VirusTotal and save results in a JSON file.
    """
    results = {}
    ips = extract_ips(top_ip_file)

    for ip in ips:
        print(f"Fetching data for IP: {ip}")
        report = fetch_vt_report(ip)

        if report:
            results[ip] = {
                "country": report.get("data", {}).get("attributes", {}).get("country", "Unknown"),
                "network": report.get("data", {}).get("attributes", {}).get("network", "Unknown"),
                "reputation": report.get("data", {}).get("attributes", {}).get("reputation", 0),
                "last_analysis_stats": report.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}),
            }

        # Rate-limit handling: VirusTotal free tier allows 4 requests per minute
        time.sleep(15)

    # Save the results to a JSON file
    with open(output_json_file, "w") as file:
        json.dump(results, file, indent=4)

    print(f"Threat intelligence results saved to {output_json_file}")

# Call the function
analyze_ips(top_ip_file, output_json_file)

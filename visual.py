import json
import pycountry
from flask import Flask, render_template
import pandas as pd

# Initialize Flask app
app = Flask(__name__)

# Load the threat intelligence data
with open("threat_intelligence_results.json", "r") as file:
    data = json.load(file)

# Function to get full country name from country code
def get_country_name(country_code):
    try:
        country = pycountry.countries.get(alpha_2=country_code)
        return country.name if country else 'Unknown'
    except KeyError:
        return 'Unknown'

# Process the data into a structured format
ip_info = []
for ip, report in data.items():
    last_analysis_stats = report.get('last_analysis_stats', {})
    country_name = get_country_name(report.get('country', ''))
    ip_info.append({
        "IP": ip,
        "Country": country_name,
        "Network": report.get('network', 'Unknown'),
        "Reputation": report.get('reputation', 0),
        "Harmless": last_analysis_stats.get('harmless', 0),
        "Malicious": last_analysis_stats.get('malicious', 0),
        "Suspicious": last_analysis_stats.get('suspicious', 0),
        "Undetected": last_analysis_stats.get('undetected', 0),
        "Timeout": last_analysis_stats.get('timeout', 0),
    })

# Sort the data by malicious count to get the top 10
top_10_ips = sorted(ip_info, key=lambda x: x['Malicious'], reverse=True)[:10]

# Route to the dashboard
@app.route('/')
def dashboard():
    return render_template('dashboard.html', ips=top_10_ips)

# Run the app
if __name__ == "__main__":
    app.run(debug=True)

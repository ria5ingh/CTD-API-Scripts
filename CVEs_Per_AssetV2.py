import requests
import urllib3
import sys
import csv
import datetime
import json
import getpass

urllib3.disable_warnings()

def authenticate(ctd_ip, username, password):
    """Authenticates with the CTD server and returns the API headers."""
    print(f"\nAuthenticating to CTD at https://{ctd_ip}...")
    auth_payload = {"username": username, "password": password}
    
    try:
        response = requests.post(f"https://{ctd_ip}/auth/authenticate", verify=False, json=auth_payload)
        auth_data = response.json()
    except requests.exceptions.RequestException as e:
        print(f"Connection Error: {e}")
        sys.exit(1)

    if "error" in auth_data:
        print("Authentication Failed:", auth_data['error'])
        sys.exit(1)

    print("Successful Login.\n")
    return {
        'Authorization': auth_data['token'],
        'Content-Type': 'application/json'
    }

def get_time_filter():
    """Prompts the user for a timeframe and calculates the UTC cutoff date."""
    days_input = input("Enter the number of days to look back for new assets (leave blank for all time): ").strip()
    
    if days_input.isdigit():
        cutoff_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=int(days_input))
        print(f"Filtering for assets first seen after: {cutoff_date.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
        return cutoff_date
    else:
        print("No time filter applied. Pulling all assets.\n")
        return None

def get_output_preference():
    """Prompts the user to choose between CSV or JSON output."""
    while True:
        choice = input("Would you like the output in CSV or JSON format? (Enter 'csv' or 'json'): ").strip().lower()
        if choice in ['csv', 'json']:
            return choice
        print("Invalid input. Please type 'csv' or 'json'.")

def fetch_assets(ctd_ip, headers, cutoff_date):
    """Fetches all valid unicast assets and initializes mapping dictionaries."""
    print("Fetching all valid assets...")
    asset_cve_counts = {}
    asset_cve_mapping = {}
    asset_info = {}
    page = 1
    
    while True:
        params = {
            'page': str(page),
            'per_page': '500',
            'ghost__exact': 'false', 
            'valid__exact': 'true', 
            'special_hint__exact': '0'
        }
        
        response = requests.get(f"https://{ctd_ip}/ranger/assets", verify=False, headers=headers, params=params)
        data = response.json()
        
        if 'objects' in data and data['objects']:
            for asset in data['objects']:
                
                # Apply time filter if one was set
                if cutoff_date:
                    asset_time_str = asset.get('first_seen') or asset.get('timestamp')
                    if asset_time_str:
                        try:
                            asset_date = datetime.datetime.fromisoformat(asset_time_str)
                            if asset_date < cutoff_date:
                                continue
                        except ValueError:
                            pass
                
                a_id = asset['id']
                a_name = asset.get('name') or asset.get('hostname') or ""
                ipv4_list = asset.get('ipv4', [])
                a_ip = ipv4_list[0] if isinstance(ipv4_list, list) and len(ipv4_list) > 0 else "" 
                
                asset_info[a_id] = {'name': a_name, 'ip': a_ip}
                asset_cve_counts[a_id] = 0
                asset_cve_mapping[a_id] = []
                
            page += 1
        else:
            break
            
    print(f"Number of valid assets tracked: {len(asset_cve_counts)}\n")
    return asset_cve_counts, asset_cve_mapping, asset_info

def fetch_cves(ctd_ip, headers, asset_cve_counts, asset_cve_mapping):
    """Fetches confirmed CVE mappings and updates the dictionaries."""
    print("Fetching confirmed CVEs that map to assets...")
    page = 1
    
    while True:
        params = {
            'page': str(page),
            'per_page': '500'
        }
        
        response = requests.get(f"https://{ctd_ip}/ranger/asset-vulnerabilities", verify=False, headers=headers, params=params)
        data = response.json()
        
        if 'objects' in data and data['objects']:
            for mapping in data['objects']:
                a_id = mapping.get('asset_id')
                relevance = mapping.get('relevance')
                
                if a_id in asset_cve_counts and relevance == 1:
                    cve_id = mapping.get('cve_id')
                    asset_cve_counts[a_id] += 1
                    asset_cve_mapping[a_id].append(cve_id)
            page += 1
        else:
            break

def export_to_csv(timestamp, asset_cve_counts, asset_cve_mapping, asset_info):
    """Handles writing the data to CSV files."""
    csv1_filename = f"assets_cve_counts_list_{timestamp}.csv"
    with open(csv1_filename, mode='w', newline='', encoding='utf-8') as f1:
        writer1 = csv.DictWriter(f1, fieldnames=['asset_id', 'cve_count'])
        writer1.writeheader()
        for a_id, count in asset_cve_counts.items():
            writer1.writerow({'asset_id': a_id, 'cve_count': count})
            
    csv2_filename = f"cves_per_assets_list_{timestamp}.csv"
    with open(csv2_filename, mode='w', newline='', encoding='utf-8') as f2:
        writer2 = csv.DictWriter(f2, fieldnames=['asset_id', 'asset_name', 'asset_ip', 'cve_id'])
        writer2.writeheader()
        for a_id, cve_list in asset_cve_mapping.items():
            if not cve_list:
                continue
            name = asset_info[a_id]['name']
            ip = asset_info[a_id]['ip']
            for cve in cve_list:
                writer2.writerow({'asset_id': a_id, 'asset_name': name, 'asset_ip': ip, 'cve_id': cve})
                
    print(f"\nCSVs Exported:\n - {csv1_filename}\n - {csv2_filename}")

def export_to_json(timestamp, asset_cve_mapping, asset_info):
    """Handles writing the data to a formatted JSON file."""
    json_filename = f"cves_per_assets_list_{timestamp}.json"
    output_data = []
    
    for a_id, cves in asset_cve_mapping.items():
        # Only include assets that actually have confirmed CVEs
        if cves:
            output_data.append({
                "asset id": a_id,
                "asset name": asset_info[a_id]['name'],
                "asset ip": asset_info[a_id]['ip'],
                "vulnerabilities": cves
            })
            
    with open(json_filename, mode='w', encoding='utf-8') as json_file:
        json.dump(output_data, json_file, indent=4)
        
    print(f"\nJSON Exported:\n - {json_filename}")

def main():
    """Main orchestration function."""
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # User Inputs
    ctd_ip = input("Enter CTD IP or hostname: ").strip()
    username = input("Enter CTD username: ").strip()
    password = getpass.getpass("Enter CTD password: ").strip()
    headers = authenticate(ctd_ip, username, password)

    output_format = get_output_preference()
    cutoff_date = get_time_filter()
    
    # API Calls
    asset_cve_counts, asset_cve_mapping, asset_info = fetch_assets(ctd_ip, headers, cutoff_date)
    fetch_cves(ctd_ip, headers, asset_cve_counts, asset_cve_mapping)
    
    # Tally up the vulnerable assets using a counter variable
    assets_with_vulns = 0
    for cves in asset_cve_mapping.values():
        if cves:
            assets_with_vulns += 1
            
    print(f"\nTotal assets with confirmed vulnerabilities: {assets_with_vulns}")
    
    # Export Routing
    if output_format == 'csv':
        export_to_csv(timestamp, asset_cve_counts, asset_cve_mapping, asset_info)
    elif output_format == 'json':
        export_to_json(timestamp, asset_cve_mapping, asset_info)
        
    print("\nScript execution complete.")

if __name__ == "__main__":
    main()
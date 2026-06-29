# =============================================================================
# Script Metadata
# -----------------------------------------------------------------------------
# Author     : Randy Benn & Ria Singh
#
# Description:
# This script connects to a Claroty CTD server, authenticates, and retrieves 
# a list of confirmed CVEs along with associated assets. Output is modularized
# and can be exported to either CSV or a nested JSON format based on user input.
# It also includes an optional time filter to only pull recently seen assets.
# =============================================================================

import requests
import urllib3
import json
import datetime
import sys
import csv
import getpass

urllib3.disable_warnings()

def authenticate(ctd_ip, username, password):
    """Authenticates with the CTD server and returns the authorization token."""
    print(f"\nAuthenticating to CTD at https://{ctd_ip}...")
    auth = {"username": username, "password": password}
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

    try:
        response = requests.post(f"https://{ctd_ip}/auth/authenticate", verify=False, headers=headers, data=json.dumps(auth))
        auth_data = response.json()
    except requests.exceptions.RequestException as e:
        print(f"Connection Error: {e}")
        sys.exit(1)

    if "error" in auth_data:
        print("Authentication Failed:", auth_data['error'])
        sys.exit(1)

    print("Successful Login.\n")
    return auth_data['token']

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

def fetch_confirmed_cves(ctd_ip, auth_token):
    """Fetches a list of CVEs that have confirmed assets attached."""
    print("Fetching confirmed CVEs...")
    
    headers = {'Authorization': auth_token}
    cve_list = []
    valid_count = 0
    skipped_count = 0
    page = 1

    while True:
        params = {
            'page': str(page),
            'per_page': '500',
            'site_id__exact': '1',
            'ghost__exact': 'false',
            'valid__exact': 'true',        
            'special_hint__exact': '0' 
        }

        response = requests.get(f"https://{ctd_ip}/ranger/vulnerabilities", verify=False, headers=headers, params=params)
        data = response.json()

        if 'objects' in data and isinstance(data['objects'], list) and data['objects']:
            for v in data['objects']:
                cve_id = v.get('cve_id')
                assets_count_data = v.get('assets_count', {})
                confirmed_count = assets_count_data.get('confirmed_assets_count', 0)

                if cve_id and confirmed_count > 0:
                    cve_list.append(cve_id)
                    valid_count += 1
                else:
                    skipped_count += 1
            page += 1
        else:
            break

    print("CVE list complete.")
    return cve_list, valid_count, skipped_count

def fetch_assets_per_cve(ctd_ip, auth_token, cve_list, cutoff_date):
    """Loops through the confirmed CVE list and pulls the associated assets with a time filter."""
    headers = {'Authorization': auth_token}
    auth_data_body = json.dumps({'auth': 'inherit auth from parent'})
    master_cve_data = {}
    
    cve_counter = 1
    total_cves = len(cve_list)

    for cve_id in cve_list:
        print(f"{cve_counter} / {total_cves} Processing assets for: {cve_id}")
        cve_counter += 1
        
        params = {
            'per_page': '500',
            'cve_id__exact': cve_id,
            'affected_assets__exact': 'true',
            'ghost__exact': 'false',
            'special_hint__exact': '0'
        }

        response = requests.get(f"https://{ctd_ip}/ranger/assets", verify=False, stream=True, 
                                data=auth_data_body, headers=headers, params=params)
        data = response.json()

        valid_assets = []

        if 'objects' in data and data['objects']:
            for asset in data['objects']:
                
                # Apply time filter if one was set
                if cutoff_date:
                    asset_time_str = asset.get('first_seen') or asset.get('timestamp')
                    if asset_time_str:
                        try:
                            asset_date = datetime.datetime.fromisoformat(asset_time_str)
                            if asset_date < cutoff_date:
                                continue  # Skip assets older than the cutoff
                        except ValueError:
                            pass
                
                valid_assets.append(asset)

        # Store the filtered asset list under the CVE ID key
        master_cve_data[cve_id] = valid_assets

    return master_cve_data

def export_to_csv(timestamp, master_cve_data):
    """Flattens the lists and exports the data to standard CSV files."""
    # 1. Export the high-level CVE summary (counting only assets that passed the time filter)
    cve_filename = f"cve_ids_list_{timestamp}.csv"
    with open(cve_filename, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['cve_id', 'filtered_assets_count'])
        for cve_id, asset_list in master_cve_data.items():
            # Only write CVEs that still have assets after filtering
            if asset_list:
                writer.writerow([cve_id, len(asset_list)])

    # 2. Export the detailed Asset mappings
    asset_filename = f"assets_per_cve_list_{timestamp}.csv"
    asset_fieldnames = ['source_cve_id','Item','id','class_type','name', 'ipv4', 'ipv6','mac',
                        'vendor','os','model','firmware','serial_number','num_alerts','insight_names']

    with open(asset_filename, mode='w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=asset_fieldnames, extrasaction='ignore')
        writer.writeheader()

        for cve_id, asset_list in master_cve_data.items():
            for i, asset in enumerate(asset_list, start=1):
                asset['Item'] = i
                asset['source_cve_id'] = cve_id
                
                # Flatten lists for CSV writing
                for key in asset_fieldnames:
                    if key not in asset:
                        continue
                    value = asset.get(key)
                    if isinstance(value, list):
                        asset[key] = ", ".join(str(v) for v in value)

            if asset_list:
                writer.writerows(asset_list)

    print(f"\nCSVs Exported:\n - {cve_filename}\n - {asset_filename}")

def export_to_json(timestamp, master_cve_data):
    """Parses the data into the requested nested JSON schema and exports."""
    json_filename = f"assets_per_cve_list_{timestamp}.json"
    output_data = []

    for cve_id, asset_list in master_cve_data.items():
        # Skip CVEs that have 0 assets after the time filter
        if not asset_list:
            continue

        asset_mapping = {}
        
        for asset in asset_list:
            a_id = str(asset.get('id', ''))
            a_name = asset.get('name') or asset.get('hostname') or "None"
            
            # Safely extract the first IPv4 address
            ipv4_list = asset.get('ipv4', [])
            a_ip = ipv4_list[0] if isinstance(ipv4_list, list) and len(ipv4_list) > 0 else "None"
            
            asset_mapping[a_id] = [a_name, a_ip]

        # Append to the main output list following the requested schema
        output_data.append({
            "cve id": cve_id,
            "asset list": asset_mapping
        })

    with open(json_filename, mode='w', encoding='utf-8') as json_file:
        json.dump(output_data, json_file, indent=4)

    print(f"\nJSON Exported:\n - {json_filename}")

def main():
    current_date = datetime.date.today()
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    # Setup & Authentication
    ctd_ip = input("Enter CTD IP or hostname: ").strip()
    username = input("Enter CTD username: ").strip()
    password = getpass.getpass("Enter CTD password: ").strip()
    auth_token = authenticate(ctd_ip, username, password)

    output_format = get_output_preference()
    cutoff_date = get_time_filter()

    print(f"Date: {current_date}\n")

    # Fetch Data
    cve_list, valid_count, skipped_count = fetch_confirmed_cves(ctd_ip, auth_token)
    
    if valid_count == 0:
        print("No confirmed CVEs found. Exiting.")
        sys.exit(0)

    # Pass the cutoff_date into the asset fetcher
    master_cve_data = fetch_assets_per_cve(ctd_ip, auth_token, cve_list, cutoff_date)

    # Print Terminal Summary
    print("\nSummary of CVE Processing")
    print("-" * 42)
    print(f"{'Status':<31} {'Count':>10}")
    print("-" * 42)
    print(f"{'Confirmed CVEs':<30} {valid_count:>10,}")
    print(f"{'Potential CVEs (skipped)':<30} {skipped_count:>10,}")
    print("-" * 42)
    print(f"{'Total processed CVEs':<30} {valid_count + skipped_count:>10,}")

    # Route Output
    if output_format == 'csv':
        export_to_csv(timestamp, master_cve_data)
    elif output_format == 'json':
        export_to_json(timestamp, master_cve_data)

    print("\nScript execution complete.")

if __name__ == "__main__":
    main()
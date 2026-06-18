import requests
import urllib3
import json
import sys
import csv
import datetime

urllib3.disable_warnings()

#Authentication
current_date = datetime.date.today()
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

ctd_ip = input("Enter CTD IP or hostname: ").strip()
username = input("Enter CTD username: ").strip()
password = input("Enter CTD password: ").strip()

auth = {"username": username, "password": password}
headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

print(f"\nAuthenticating to CTD at https://{ctd_ip}...")
doauth = requests.post(f"https://{ctd_ip}/auth/authenticate", verify=False, headers=headers, data=json.dumps(auth))
check_user_pass = doauth.json()

if "error" in check_user_pass:
    print("ERROR: Authentication Failed:", check_user_pass['error'])
    sys.exit(0)

print("Successful Login\n")

ctd_auth_token = check_user_pass['token']
getauthheaders = {'Authorization': ctd_auth_token}
getauthdata = {'auth': 'inherit auth from parent'}

#CSV setup
asset_filename = f"total_assets_{timestamp}.csv"
asset_fieldnames = ['id', 'name', 'ipv4', 'ipv6', 'vendor', 'model']
total_assets_processed = 0
skipped_assets_count = 0

#Fetch All Assets
with open(asset_filename, mode='w', newline='', encoding='utf-8') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=asset_fieldnames)
    writer.writeheader()

    page = 1
    while True:
        print(f"Fetching Assets: page {page}...")
        
        # Parameters for fetching assets
        asset_params = {
            'page': str(page),
            'per_page': '500',
            'ghost__exact': 'false',
            'valid__exact': 'true',         # Filters out deleted/aged-out assets
            'special_hint__exact': '0'      # 0 = eUnicast (filters out Multicast/Broadcast via API)
        }

        response = requests.get(f"https://{ctd_ip}/ranger/assets",
                                verify=False, stream=True,
                                data=json.dumps(getauthdata),
                                headers=getauthheaders, params=asset_params)

        data = response.json()

        # Check if we have objects on the current page
        if 'objects' in data and isinstance(data['objects'], list) and data['objects']:
            asset_list = data['objects']
            
            for asset in asset_list:
                
                asset_name = str(asset.get('name', '')).lower()
                
                if "(multicast)" in asset_name or "(broadcast)" in asset_name:
                    skipped_assets_count += 1
                    continue

                row_data = {}
                
                for field in asset_fieldnames:
                    value = asset.get(field)
                    
                    if value is None:
                        row_data[field] = "None"
                    elif isinstance(value, list):
                        if len(value) == 0:
                            row_data[field] = "None"
                        else:
                            row_data[field] = ", ".join(str(v) for v in value)
                    else:
                        row_data[field] = str(value).strip() or "None"
                
                writer.writerow(row_data)
                total_assets_processed += 1
            
            page += 1
        else:
            print("Asset extraction complete.\n")
            break

#Final Summary
print("Summary of Asset Processing")
print("-" * 35)
print(f"Total valid assets saved : {total_assets_processed:,}")
print(f"Network groups skipped  : {skipped_assets_count:,}")
print(f"Data written to file    : {asset_filename}")
print("-" * 35)
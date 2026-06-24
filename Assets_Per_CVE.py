# =============================================================================
# 📄 Script Metadata
# -----------------------------------------------------------------------------
# Date       : 2025-08-05
# Author     : Randy Benn
# Version    : 1.4
# Contact    : randy.b@clarotygov.us
#
# 📝 Description:
# This script connects to a Claroty CTD (Continuous Threat Detection) server,
# authenticates using provided credentials, and retrieves a list of confirmed
# CVEs (Common Vulnerabilities and Exposures) along with associated assets.
# Output is written to a CSV file which can be opened in Excel or other 
# spreadsheet application.
#
# Instructions:
# Edit the details in the 'CTD Server Info' section below.
# No further edits are required.
# 
# =============================================================================

import requests
import urllib3
import json
import datetime
import sys
import csv

urllib3.disable_warnings()

# 📅 Setup date and timestamp
current_date = datetime.date.today()
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

# 🔐 CTD Server Info
ctd_ip = input("Enter CTD IP or hostname: ").strip()
username = input("Enter CTD username: ").strip()
password = input("Enter CTD password: ").strip()

# 🔑 Authentication
auth = {"username": username, "password": password}
headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

doauth = requests.post(f"https://{ctd_ip}/auth/authenticate", verify=False, headers=headers, data=json.dumps(auth))
check_user_pass = doauth.json()
if "error" in check_user_pass:
    print("❌ Authentication Failed:", check_user_pass['error'])
    sys.exit(0)

print("✅ Successful Login")

ctd_auth_token = check_user_pass['token']
getauthheaders = {'Authorization': ctd_auth_token}
getauthdata = {'auth': 'inherit auth from parent'}

print(f"🔗 Connecting to CTD at https://{ctd_ip}")
print(f"📆 Date: {current_date}\n")

# 📄 CSV setup for CVEs
cve_filename = f"cve_ids_list_{timestamp}.csv"
cve_fieldnames = ['cve_id', 'confirmed_assets_count']

valid_count = 0
skipped_count = 0
cve_list = []

# 📦 Fetch confirmed CVEs
with open(cve_filename, mode='w', newline='', encoding='utf-8') as cve_csvfile:
    cve_writer = csv.DictWriter(cve_csvfile, fieldnames=cve_fieldnames)
    cve_writer.writeheader()

    page = 1
    while True:
        print(f"📄 Fetching CVEs: page {page}...")
        asset_params = {
            'page': str(page),
            'per_page': '500',
            'site_id__exact': '1',
            'ghost__exact': 'false',
            'valid__exact': 'true',        
            'special_hint__exact': '0' # 0 = eUnicast
        }

        assets_response = requests.get(f"https://{ctd_ip}/ranger/vulnerabilities",
                                       verify=False, headers=getauthheaders, params=asset_params)
        data = assets_response.json()

        if 'objects' in data and isinstance(data['objects'], list) and data['objects']:
            for v in data['objects']:
                cve_id = v.get('cve_id')
                assets_count_data = v.get('assets_count', {})
                confirmed_count = assets_count_data.get('confirmed_assets_count', 0)

                if cve_id and confirmed_count > 0:
                    cve_writer.writerow({'cve_id': cve_id, 'confirmed_assets_count': confirmed_count})
                    cve_list.append(cve_id)
                    valid_count += 1
                else:
                    skipped_count += 1
            page += 1
        else:
            print("✅ CVE list complete. No more data found.")
            break

# 📊 CVE Summary
# print(f"\n📦 Filtered CVE list exported to file: {cve_filename}")
print(f"✅ Confirmed CVEs: {valid_count:,}")
print(f"🚫 Potential CVEs (skipped): {skipped_count:,}")
print(f"📊 Total CVEs processed: {valid_count + skipped_count:,}\n")

# 📁 Combined output CSV for all assets
asset_filename = f"assets_per_cve_list{timestamp}.csv"
asset_fieldnames = ['source_cve_id','Item','id','class_type','name', 'ipv4', 'ipv6','mac','vendor','os','model',
                    'firmware','serial_number','num_alerts','insight_names']

with open(asset_filename, mode='w', newline='', encoding='utf-8') as csvfile:
    csvfile.write("Assets Per CVE - Aggregated Output\n")
    writer = csv.DictWriter(csvfile, fieldnames=asset_fieldnames, extrasaction='ignore')
    writer.writeheader()

    # 🔍 Loop through each CVE and fetch asset data
    cve_counter = 1  # Start counter

    for cve_id in cve_list:
        print(f"{cve_counter} / {valid_count} 🔍 Processing assets for: {cve_id}")
        cve_counter += 1
        params_data = {
            'per_page': '500',
            'cve_id__exact': cve_id,
            'affected_assets__exact': 'true',
            'ghost__exact': 'false',
            'special_hint__exact': '0'
        }

        response = requests.get(f"https://{ctd_ip}/ranger/assets",
                                verify=False, stream=True,
                                data=json.dumps(getauthdata),
                                headers=getauthheaders, params=params_data)

        data = response.json()

        if 'objects' in data and data['objects']:
            asset_list = data['objects']

            # Flatten lists
            for asset in asset_list:
                for key in asset_fieldnames:
                    if key not in asset:
                        continue
                    value = asset.get(key)
                    if isinstance(value, list):
                        asset[key] = ", ".join(str(v) for v in value)

            for i, asset in enumerate(asset_list, start=1):
                asset['Item'] = i
                asset['source_cve_id'] = cve_id

            writer.writerows(asset_list)
            print(f"✅ Added {len(asset_list)} assets for {cve_id}")
        else:
            print(f"⚠️ No assets found for CVE: {cve_id}")

print()
print("\nSummary of CVE Processing\n" + "-"*42)
print(f"{'Status':<31} {'Count':>10}")
print("-"*42)
print(f"{'✅ Confirmed CVEs':<30} {valid_count:>10,}")
print(f"{'🚫 Potential CVEs (skipped)':<30} {skipped_count:>10,}")
print("-"*42)
print(f"{'📊 Total processed CVEs':<30} {valid_count + skipped_count:>10,}")

print(f"\n📦 All data written to file: {asset_filename}")
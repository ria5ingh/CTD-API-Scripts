import requests
import urllib3
import sys
import csv
import datetime
import json
import getpass


urllib3.disable_warnings()

#authentication
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

ctd_ip = input("Enter CTD IP or hostname: ").strip()
username = input("Enter CTD username: ").strip()
password = getpass.getpass("Enter CTD password: ").strip()

auth_payload = {"username": username, "password": password}
doauth = requests.post(f"https://{ctd_ip}/auth/authenticate", verify=False, json=auth_payload)
auth_data = doauth.json()

if "error" in auth_data:
    print("Authentication Failed:", auth_data['error'])
    sys.exit(0)

headers = {
    'Authorization': auth_data['token'],
    'Content-Type': 'application/json'
}
print("Successful Login.\n")


#dict 1: enumerates all assets and maps asset_id : number of confirmed CVEs
asset_cve_counts = {}

#dict 2: maps asset_id : list of cve_ids
asset_cve_mapping = {}

#dict 3: maps asset_id : {name, ipv4}
asset_info = {}

#get all assets
print("Fetching all assets")
page = 1
while True:
    params = {
        'page': str(page),
        'per_page': '500',
        'ghost__exact': 'false', #get non-ghost assets
        'valid__exact': 'true', 
        'special_hint__exact': '0' # 0 = eUnicast 
    }
    
    response = requests.get(f"https://{ctd_ip}/ranger/assets", verify=False, headers=headers, params=params)
    data = response.json()
    
    if 'objects' in data and data['objects']:
        for asset in data['objects']:
            a_id = asset['id']

            a_name = asset.get('name') or asset.get('hostname') or ""
            ipv4_list = asset.get('ipv4', [])
            a_ip = ipv4_list[0] if isinstance(ipv4_list, list) and len(ipv4_list) > 0 else "" 
            asset_info[a_id] = {'name': a_name, 'ip': a_ip}

            #initialize both dicts with 0 counts for all assets
            asset_cve_counts[a_id] = 0
            asset_cve_mapping[a_id] = []
        page += 1
    else:
        break

print(f"Number of Assets (non-ghost): {len(asset_cve_counts)}\n")


#populate dictionaries
print("Fetching confirmed CVEs that map to assets.")
page = 1
while True:
    params = {
        'page': str(page),
        'per_page': '500'
    }
    
    response = requests.get(f"https://{ctd_ip}/ranger/asset-vulnerabilities", verify=False, headers=headers, params=params)
    data = response.json()
    
    if 'objects' in data and data['objects']:
        #loop through each cve-asset mapping and populate dicts
        for mapping in data['objects']:
            a_id = mapping.get('asset_id')
            relevance = mapping.get('relevance')
            
            #only get cves where asset exists in our non-ghost dict AND relevance is 1 (confirmed CVE)
            if a_id in asset_cve_counts and relevance == 1:
                cve_id = mapping.get('cve_id')
                
                #increment the cve countm append to mapping list
                asset_cve_counts[a_id] += 1
                asset_cve_mapping[a_id].append(cve_id)
        page += 1
    else:
        break

#write to CSVs
#"assets_cve_counts_list{time}.csv" stores asset_id and count of confirmed cves per asset
csv1_filename = f"assets_cve_counts_list_{timestamp}.csv"
csv1_fields = ['asset_id', 'cve_count']

with open(csv1_filename, mode='w', newline='', encoding='utf-8') as f1:
    writer1 = csv.DictWriter(f1, fieldnames=csv1_fields)
    writer1.writeheader()
    
    for a_id, count in asset_cve_counts.items():
        writer1.writerow({
            'asset_id': a_id, 
            'cve_count': count
        })
print(f"Asset IDs and CVE counts saved to: {csv1_filename}")

#"cves_per_assets_list{time}.csv" stores all cves per asset (only writes assets WITH confirmed cves)
csv2_filename = f"cves_per_asset_list_{timestamp}.csv"
csv2_fields = ['asset_id', 'asset_name', 'asset_ip', 'cve_id']

with open(csv2_filename, mode='w', newline='', encoding='utf-8') as f2:
    writer2 = csv.DictWriter(f2, fieldnames=csv2_fields)
    writer2.writeheader()
    
    for a_id, cve_list in asset_cve_mapping.items():
        #get the name and IP
        name = asset_info[a_id]['name']
        ip = asset_info[a_id]['ip']
        
        #if cve_list is empty, this loop is ignored
        for cve in cve_list:
            writer2.writerow({
                'asset_id': a_id,
                'asset_name': name,
                'asset_ip': ip,
                'cve_id': cve
            })
print(f"CVEs per Asset List saved to: {csv2_filename}")

#print results
print("All Assets and CVE Counts:")

#print the asset_cve_counts dict
for k, v in list(asset_cve_counts.items()):
    print(f"Asset ID: {k} | Confirmed CVEs: {v}")


print("\nCVEs per Asset:")
#print the asset_cve_mapping dict
for k, v in list(asset_cve_mapping.items()):
    print(f"Asset ID: {k} | CVE List: {v}")



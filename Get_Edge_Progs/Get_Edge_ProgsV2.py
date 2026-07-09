from getpass import getpass
import json
import requests
import datetime
import sys
import urllib3
import csv
from collections import defaultdict
import getpass

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def authenticate(ctd_ip, username, password):
    auth_payload = {"username": username, "password": password}
    
    try:
        response = requests.post(f"https://{ctd_ip}/auth/authenticate", verify=False, json=auth_payload)
        auth_data = response.json()
    except requests.exceptions.RequestException as e:
        print(f"Failed to connect to the server: {e}")
        sys.exit(1)
    except ValueError:
        print("Authentication Failed: Server did not return valid JSON.")
        sys.exit(1)

    if "error" in auth_data:
        print("Authentication Failed:", auth_data['error'])
        sys.exit(1)

    token = auth_data.get('token')
    if not token:
        print("Authentication Failed: No token returned by the server.")
        sys.exit(1)

    print("Successful Login.\n")
    return {
        'Authorization': token,
        'Content-Type': 'application/json'
    }

def find_windows_edge_host(ctd_ip, headers):
    print("Querying assets for a Windows host with an active edge_id.")
    asset_page = 1
    asset_per_page = 500
    
    while True:
        asset_endpoint = f"/ranger/assets?fields=resource_id,;$edge_id,;$os&page={asset_page}&per_page={asset_per_page}"
        url = f"https://{ctd_ip}{asset_endpoint}"
        
        try:
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            asset_data = response.json()
            
            objects = asset_data.get("objects", [])
            
            for asset in objects:
                r_id = asset.get('resource_id')
                edge_id = asset.get(';$edge_id', asset.get('edge_id'))
                os_name = asset.get(';$os', asset.get('os', '')).lower()
                
                if edge_id is not None and isinstance(os_name, str):
                    if "windows" in os_name:
                        print(f"Windows Edge Host Found: Asset ID: {r_id} | OS: {os_name} | Edge ID: {edge_id}\n")
                        return r_id 
            
            if len(objects) < asset_per_page:
                break
                
            asset_page += 1
            
        except Exception as e:
            print(f"Failed to fetch assets: {e}")
            sys.exit(1)
            
    return None

def fetch_installed_programs(ctd_ip, headers, edge_host_id):
    print("Fetching installed programs...")
    all_programs = []
    page = 1
    per_page = 50 
    
    while True:
        endpoint = f"/ranger/ranger_api/asset_installed_programs?fields=name,;$version,;$vendor&sort=name&page={page}&per_page={per_page}&asset_rid__exact={edge_host_id}"
        url = f"https://{ctd_ip}{endpoint}"
        
        try:
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()
            
            data = response.json()
            objects = data.get("objects", [])
            all_programs.extend(objects)
            
            if len(objects) < per_page:
                break
                
            page += 1
            
        except requests.exceptions.RequestException:
            break
        except ValueError:
            break
            
    return all_programs

def load_cve_matcher_map(csv_filepath):
    matcher_map = defaultdict(list)
    try:
        with open(csv_filepath, mode='r', encoding='utf-8') as f:
            reader = csv.reader(f)
            next(reader, None) 
            for row in reader:
                if len(row) >= 2:
                    vendor = row[0].strip().lower()
                    program = row[1].strip().lower()
                    if vendor and program:
                        matcher_map[vendor].append(program)
        print(f"Loaded {sum(len(v) for v in matcher_map.values())} programs across {len(matcher_map)} vendors from {csv_filepath}.\n")
    except FileNotFoundError:
        print(f"WARNING: {csv_filepath} not found.\n")
    
    return matcher_map

#Checks if the vendor matches and if the CSV program string is inside the API program string.
def check_in_ctd(api_vendor, api_program, matcher_map):
    if not matcher_map:
        return "no"
        
    api_vendor_norm = api_vendor.strip().lower()
    api_prog_norm = api_program.strip().lower()

    if api_vendor_norm in matcher_map:
        for csv_program in matcher_map[api_vendor_norm]:
            if csv_program in api_prog_norm:
                return "yes"
                
    return "no"

def main():
    #User Inputs
    ctd_ip = input("Enter CTD IP or hostname: ").strip()
    username = input("Enter CTD username: ").strip()
    password = getpass.getpass("Enter CTD password: ").strip()
    
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"windows_programs_list_{timestamp}.csv"
    
    #cve_program_matcher_cut.csv supplied in github repo. SHOULD be in the same directory as this script.
    matcher_csv = "cve_program_matcher_cut.csv"
    matcher_map = load_cve_matcher_map(matcher_csv)

    headers = authenticate(ctd_ip, username, password)
    edge_host_id = find_windows_edge_host(ctd_ip, headers)
    if not edge_host_id:
        print("No Windows edge hosts found. Exiting.")
        sys.exit(0)

    programs_list = fetch_installed_programs(ctd_ip, headers, edge_host_id)

    try:
        with open(filename, mode='w', newline='', encoding='utf-8') as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(['program', 'vendor', 'version', 'in_CTD'])            
            for obj in programs_list:
                program = obj.get('name', '')
                vendor = obj.get(';$vendor', obj.get('vendor', ''))
                version = obj.get(';$version', obj.get('version', ''))
                in_ctd_status = check_in_ctd(vendor, program, matcher_map)
                
                writer.writerow([program, vendor, version, in_ctd_status])
                print(f"{program}, {vendor}, {version}, {in_ctd_status}")

    except Exception as e:
        print(f"Failed to write to CSV: {e}")
        sys.exit(1)

    #terminal Output
    print(f"Total programs found: {len(programs_list)}")
    print(f"Exported to {filename}")

if __name__ == "__main__":
    main()
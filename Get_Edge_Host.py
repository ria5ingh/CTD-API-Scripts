import requests
import urllib3
import sys
import csv
import datetime
import json
import getpass


urllib3.disable_warnings()

def main():
    #authentication
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

    #extract first matching edge host ID
    print("Querying assets for a Windows host with an active edge_id.")
    edge_host_id = None
    asset_page = 1
    asset_per_page = 500
    
    while True:
        asset_endpoint = f"/ranger/assets?fields=resource_id,;$edge_id,;$os&page={asset_page}&per_page={asset_per_page}"
        asset_url = f"https://{ctd_ip}{asset_endpoint}"
        
        try:
            asset_response = requests.get(asset_url, headers=headers, verify=False)
            asset_response.raise_for_status()
            asset_data = asset_response.json()
            
            objects = asset_data.get("objects", [])
            
            for asset in objects:
                r_id = asset.get('resource_id')
                edge_id = asset.get(';$edge_id', asset.get('edge_id'))
                os_name = asset.get(';$os', asset.get('os', '')).lower()
                
                #check if edge_id is not null AND OS is Windows
                if edge_id is not None and isinstance(os_name, str):
                    if "windows" in os_name:
                        edge_host_id = r_id
                        print(f"Match found. Asset ID: {edge_host_id} | OS: {os_name} | Edge ID: {edge_id}\n")
                        break 
            
            if edge_host_id:
                break
                
            if len(objects) < asset_per_page:
                break
                
            asset_page += 1
            
        except Exception as e:
            print(f"Failed to fetch assets: {e}")
            sys.exit(1)
            
    if not edge_host_id:
        print("No assets found matching the criteria (edge_id is not null and OS = Windows 10/11).")
        sys.exit(0)

if __name__ == "__main__":
    main()
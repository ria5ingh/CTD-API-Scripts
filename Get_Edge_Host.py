import requests
import urllib3
import sys
import csv
import datetime
import json

urllib3.disable_warnings()

def main():
    #authentication
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    ctd_ip = input("Enter CTD IP or hostname: ").strip()
    username = input("Enter CTD username: ").strip()
    password = input("Enter CTD password: ").strip()

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

    # 2. Automatically Extract the First Matching Edge Host ID
    print("Querying assets for a Windows 10/11 host with an active edge_id...")
    edge_host_id = None
    asset_page = 1
    asset_per_page = 500
    
    while True:
        # Requesting only resource_id, edge_id, and os for optimal performance
        asset_endpoint = f"/ranger/assets?fields=resource_id,;$edge_id,;$os&page={asset_page}&per_page={asset_per_page}"
        asset_url = f"https://{ctd_ip}{asset_endpoint}"
        
        try:
            asset_response = requests.get(asset_url, headers=headers, verify=False)
            asset_response.raise_for_status()
            asset_data = asset_response.json()
            
            objects = asset_data.get("objects", [])
            
            for asset in objects:
                # Use .get() to check both standard and API-prefixed keys
                r_id = asset.get('resource_id')
                edge_id = asset.get(';$edge_id', asset.get('edge_id'))
                os_name = asset.get(';$os', asset.get('os', ''))
                
                # Check our conditions: edge_id is not None (not null) AND OS is Windows 10 or 11
                if edge_id is not None and isinstance(os_name, str):
                    if "Windows 10" in os_name or "Windows 11" in os_name:
                        edge_host_id = r_id
                        print(f"Match found! Asset ID: {edge_host_id} | OS: {os_name} | Edge ID: {edge_id}\n")
                        break # Break out of the for-loop once we find our first match
            
            # If we found our target, break out of the while-loop
            if edge_host_id:
                break
                
            # If we reach the end of the pages without finding a match, break
            if len(objects) < asset_per_page:
                break
                
            asset_page += 1
            
        except Exception as e:
            print(f"Failed to fetch assets: {e}")
            sys.exit(1)
            
    if not edge_host_id:
        print("No assets found matching the criteria (edge_id is not null and OS = Windows 10/11). Exiting.")
        sys.exit(0)

if __name__ == "__main__":
    main()
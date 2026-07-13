import requests
import urllib3
import json
import sys
import getpass

# Disable SSL warnings for self-signed certificates common on local appliances
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def authenticate(ctd_ip, username, password):
    """Authenticates with the CTD server and returns the API headers."""
    print(f"\nAuthenticating to CTD at https://{ctd_ip}...")
    auth_payload = {"username": username, "password": password}
    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
    
    try:
        response = requests.post(f"https://{ctd_ip}/auth/authenticate", verify=False, headers=headers, data=json.dumps(auth_payload))
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

def get_target_limit():
    """Prompts user for how many assets they want to return."""
    while True:
        user_input = input("How many assets would you like to return? (Enter a number, or press Enter for ALL): ").strip()
        if user_input == "":
            return None # None represents fetching everything
        if user_input.isdigit() and int(user_input) > 0:
            return int(user_input)
        print("Invalid input. Please enter a positive integer or press Enter.")

def fetch_paginated_assets(ctd_ip, headers, limit=None):
    """Paginates through the endpoint, respecting the user's limit choice."""
    all_objects = []
    page = 1
    per_page = 500  # Default chunk size per API call
    
    # If a specific small limit is requested, don't ask for more than needed on page 1
    if limit and limit < per_page:
        per_page = limit

    print("\nStarting paginated API extraction...")
    
    while True:
        # If user defined a limit, calculate how many items are still left to fetch
        remaining = limit - len(all_objects) if limit is not None else None
        
        # Break early if we've fulfilled the user's requested total
        if remaining is not None and remaining <= 0:
            break

        # Adjust the last page size dynamically so we don't over-fetch
        current_per_page = per_page
        if remaining is not None and remaining < per_page:
            current_per_page = remaining

        print(f" - Fetching page {page} (Requesting {current_per_page} items)...")
        
        #EDIT PARAMS HERE FOR TESTING
        asset_params = {
            'page': str(page),
            'per_page': str(current_per_page),
            'ghost__exact': 'false', #default
            'valid__exact': 'true', #default
            'special_hint__exact': 0, #default for unicast
            
            #MANUALLY ADD FILTERS/FIELDS HERE FOR TESTING
            'fields' : 'custom_informations,;$display_name'
        }
        
        body_data = json.dumps({'auth': 'inherit auth from parent'})
        full_url = f"https://{ctd_ip}/ranger/assets"

        try:
            response = requests.get(full_url, verify=False, data=body_data, headers=headers, params=asset_params)
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            print(f"Error reading page {page}: {e}")
            break

        # Extract the items array
        page_objects = data.get('objects', [])
        
        if not page_objects:
            print("No more items found on the server.")
            break
            
        all_objects.extend(page_objects)
        print(f"   Collected {len(page_objects)} items. Total so far: {len(all_objects)}")
        
        # If the server returned fewer items than we asked for, it means we hit the final page
        if len(page_objects) < current_per_page:
            print("Reached the end of the server data.")
            break

        page += 1

    return all_objects

def fetch_single_asset(ctd_ip, headers, resource_id):
    """Fetches a single asset directly via its resource_id template path."""
    full_url = f"https://{ctd_ip}/ranger/assets/{resource_id}"
    print(f"\nFetching single asset from: {full_url}")
    
    body_data = json.dumps({'auth': 'inherit auth from parent'})
    asset_params = {
            'fields' : 'id,;$site_id'
    }
    
    try:
        response = requests.get(full_url, verify=False, data=body_data, headers=headers, params=asset_params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP Error trying to fetch asset '{resource_id}': {http_err}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

def main():
    # 1. Setup & Authentication
    ctd_ip = input("Enter the CTD IP address: ").strip()
    username = input("Enter the username: ").strip()
    password = input("Enter the password: ").strip()

    headers = authenticate(ctd_ip, username, password)

    # 2. Select Test Mode
    print("Select an endpoint test option:")
    print(" [1] GET /ranger/assets (List & Paginate)")
    print(" [2] GET /ranger/assets/{resource_id} (Single Asset)")
    mode = input("Enter choice (1 or 2): ").strip()

    if mode == "1":
        # 3a. Get User Limit Preference and run paginated lookup
        limit = get_target_limit()
        assets = fetch_paginated_assets(ctd_ip, headers, limit=limit)

        # 4a. Print results to terminal
        print("\n" + "=" * 60)
        print(json.dumps(assets, indent=4))
        print("=" * 60)
        print(f"FINAL OUTPUT ({len(assets)} items gathered):")

    elif mode == "2":
        # 3b. Get specific resource ID and query single endpoint
        resource_id = input("Enter the asset resource_id: ").strip()
        if not resource_id:
            print("Resource ID cannot be empty.")
            sys.exit(1)
            
        asset_data = fetch_single_asset(ctd_ip, headers, resource_id)
        
        # 4b. Print single result to terminal
        if asset_data:
            print("\n" + "=" * 60)
            print(json.dumps(asset_data, indent=4))
            print("=" * 60)
            print(f"FINAL OUTPUT: Successfully fetched asset '{resource_id}'")
        else:
            print(f"Could not retrieve data for asset '{resource_id}'.")
            
    else:
        print("Invalid menu choice. Exiting.")

if __name__ == "__main__":
    main()
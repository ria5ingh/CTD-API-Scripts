import requests
import urllib3
import urllib.parse
import json
import sys
import getpass
from dotenv import load_dotenv
import os
import datetime

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

def handle_api_response(data, endpoint_name):
    """
    Safely parses the API response. If it's not a dict with an 'objects' list,
    it prints the raw return directly to the terminal for debugging.
    """
    # Case 1: If the response is a direct list of items rather than a wrapped dictionary
    if isinstance(data, list):
        print(f"\n[NOTE] Endpoint '{endpoint_name}' returned a raw list directly (no 'objects' wrapper).")
        return data

    # Case 2: Standard expected dictionary format
    if isinstance(data, dict):
        if 'objects' in data:
            return data['objects']
        else:
            print(f"\n[WARNING] Received a dictionary from '{endpoint_name}' but 'objects' key was missing!")
            print("--- RAW API RESPONSE KEYS ---")
            print(list(data.keys()))
            print("\n--- RAW API RESPONSE CONTENT ---")
            print(json.dumps(data, indent=4))
            print("--------------------------------")
            return []
            
    # Case 3: None or unexpected string format
    print(f"\n[ERROR] Unexpected data type received from '{endpoint_name}': {type(data)}")
    print("--- RAW API RESPONSE CONTENT ---")
    print(json.dumps(data, indent=4) if data else "Empty Response (None)")
    print("--------------------------------")
    return []

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
        remaining = limit - len(all_objects) if limit is not None else None
        
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
            #'valid__exact': 'true', #default
            'special_hint__exact': 0, #default for unicast
            
            #MANUALLY ADD FILTERS/FIELDS HERE FOR TESTING
            'fields' : 'asset_type,;$name',
            #testing
            #'insight_row_key__exact': 'Managed PLCs (by Rockwell users),;$1,;$236,;$ENG_AB%5CAdministrator,;$2026-05-18T18%3A55%3A47%2B00%3A00'
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
        page_objects = handle_api_response(data, "/ranger/assets")
        
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

def fetch_assets_with_insights(ctd_ip, headers, limit=None):
    """Paginates through assets with insights (high vulnerability matching)."""
    all_objects = []
    page = 1
    per_page = 100  # Typically insights endpoints return heavier payloads, default to 100 per call
    
    if limit and limit < per_page:
        per_page = limit

    print("\nStarting paginated assets with insights extraction...")
    
    while True:
        remaining = limit - len(all_objects) if limit is not None else None
        
        if remaining is not None and remaining <= 0:
            break

        current_per_page = per_page
        if remaining is not None and remaining < per_page:
            current_per_page = remaining

        print(f" - Fetching page {page} (Requesting {current_per_page} items)...")
        
        # EDIT PARAMS HERE FOR TESTING
        # All filters on this endpoint are optional, edit below as needed

    # WORKING FIELDS (Safe to use in combinations):
    # --> name only works with the below combos
    # ['name', 'site_name', 'ipv4', 'ipv6', 'mac', 'asset_type', 'os', 'model', 'vendor', 'firmware', 'criticality', 'insights', 'total_cves_count']

    # BROKEN FIELDS (Do not use on this endpoint):
    # --> name does NOT work with these:
    # ['id', 'site_id', 'resource_id', 'ghost', 'risk_level', 'network_id']
    
    # everything works with these but 'name' 
    # all_fields = ["id", "site_id", "resource_id", "ghost", "risk_level", "site_name", "network_id", "ipv4", "ipv6", 
    #               "mac", "asset_type", "os", "model", "vendor", "firmware", "criticality", "insights", "total_cves_count"]

    # total_cves_count only works with insights


        insight_params = {
            'page': str(page),
            'per_page': str(current_per_page),
            'ghost__exact': 'false', #default
            #'valid__exact': 'true', #default
            'special_hint__exact': 0, #default for unicast
            'fields': 'name'
        }
        
        body_data = json.dumps({'auth': 'inherit auth from parent'})
        full_url = f"https://{ctd_ip}/ranger/assets_with_insights"

        try:
            response = requests.get(full_url, verify=False, data=body_data, headers=headers, params=insight_params)
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            print(f"Error reading page {page}: {e}")
            break

        page_objects = handle_api_response(data, "/ranger/assets_with_insights")
        
        if not page_objects:
            print("No more items found on the server.")
            break
            
        all_objects.extend(page_objects)
        print(f"   Collected {len(page_objects)} items. Total so far: {len(all_objects)}")
        
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

def fetch_paginated_insights_summary(ctd_ip, headers, limit=None):
    """Fetches the insights summary endpoint, cleans the data, and exports to JSON."""
    all_objects = []
    page = 1
    per_page = 50  # Recommended default from API docs
    
    print("\nStarting insights summary extraction...")
    print(f" - Fetching page {page} (Requesting insights)...")
        
    # Build query params
    summary_params = {
        'page': page,
        'per_page': per_page,
        'format' : 'insight_page',              # Default for summary
        'sort' : '-risk_level',                  # Default (order by risk level)
        'ghost__exact' : 'false',                # Default, MAY EXCLUDE
        'special_hint__exact': '0',              # Default unicast (0)
        'site_id__exact' : '1',                  # Default 1
        'insight_status__exact': '0'             # Default Open (0)
    }
        
    body_data = json.dumps({'auth': 'inherit auth from parent'})
    full_url = f"https://{ctd_ip}/ranger/insights_summary"

    try:
        response = requests.get(full_url, verify=False, data=body_data, headers=headers, params=summary_params)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"Error reading page {page}: {e}")
        if 'response' in locals() and hasattr(response, 'text'):
            print("--- RAW UNPARSED SERVER RESPONSE ---")
            print(response.text[:1000]) # Truncated to avoid flooding
            print("------------------------------------")

    page_objects = handle_api_response(data, "/ranger/insights_summary")
    
    if not page_objects:
        print("No more insights found on the server.")
    else:
        # DATA CLEANUP: Remove unwanted headers
        for obj in page_objects:
            if isinstance(obj, dict):
                obj.pop('headers', None)
                obj.pop('default_sort', None)
                obj.pop('other_side_headers', None)
                obj.pop('other_side_default_sort', None)
            
    all_objects.extend(page_objects)
    print(f"   Collected {len(page_objects)} insights. Total so far: {len(all_objects)}")

    # JSON EXPORT LOGIC
    if all_objects:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"insights_summary_{timestamp}.json"
        
        print(f"\nWriting output to file to prevent terminal flooding...")
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(all_objects, f, indent=4)
        print(f"Export complete! Data saved to: {filename}")
    else:
        print("\nNo data retrieved to save.")

    return all_objects

def fetch_insight_details(ctd_ip, headers, insight_name):
    """Paginates through the insight details endpoint and saves accumulated raw output."""
    page = 1
    per_page = 100  # Updated to 100 per page

    print(f"\nStarting {insight_name} extraction...")
    
    # Auto-encode the path segment cleanly
    import urllib.parse
    insight_path = urllib.parse.quote(insight_name)
    full_url = f"https://{ctd_ip}/ranger/insight_details/{insight_path}"

    final_data = None
    total_collected = 0

    while True:
        print(f" - Fetching page {page} (Requesting {per_page} items)...")
        
        params = {
            'format': 'insight_page',
            'page': page,
            'per_page': per_page,
            'ghost__exact' : 'false',            # Default
            'special_hint__exact': '0',         # Default unicast (0)
            'site_id__exact' : '1',             # Default 1
            'insight_status__exact': '0',        # Default Open (0)
        }
            
        body_data = json.dumps({'auth': 'inherit auth from parent'})
        data = None  

        try:
            response = requests.get(full_url, verify=False, data=body_data, headers=headers, params=params)
            response.raise_for_status()
            data = response.json()
        except Exception as e:
            print(f"Error reading page {page}: {e}")
            if 'response' in locals() and hasattr(response, 'text'):
                try:
                    data = response.json()
                except:
                    data = {"raw_text_error": response.text}
            
            # If we couldn't get any data during the error, break the loop
            if not data:
                break

        # ---------------------------------------------------------
        # MERGE PAGINATION LOGIC
        # ---------------------------------------------------------
        if isinstance(data, dict):
            # Extract the actual asset data array from the 'rows' key
            page_rows = data.get('rows', [])
            
            if not page_rows:
                print("No more rows found on this page. Stopping.")
                break
                
            if final_data is None:
                # First page: Keep the whole structure (headers, description, etc.)
                final_data = data 
            else:
                # Subsequent pages: Only append the new rows to our master structure
                final_data['rows'].extend(page_rows)
                
            total_collected += len(page_rows)
            print(f"   Collected {len(page_rows)} rows. Total so far: {total_collected}")
            
            # If the server returned fewer items than requested, we hit the end
            if len(page_rows) < per_page:
                print("Reached the end of the available server data.")
                break
                
        elif isinstance(data, list):
            # Fallback just in case a different insight returns a raw list directly
            if not data:
                break
            if final_data is None:
                final_data = []
            final_data.extend(data)
            total_collected += len(data)
            print(f"   Collected {len(data)} items. Total so far: {total_collected}")
            
            if len(data) < per_page:
                break
        else:
            # Unrecognized format, save what we got and break safely
            if final_data is None:
                final_data = data
            print("Unrecognized data format. Stopping pagination.")
            break

        # Increment for the next loop
        page += 1

    # ---------------------------------------------------------
    # RAW JSON EXPORT LOGIC 
    # ---------------------------------------------------------
    if final_data is not None:
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Replace spaces with underscores for a cleaner filename
        safe_name = insight_name.replace(" ", "_")
        filename = f"{safe_name}_details_{timestamp}.json"
        
        print(f"\nWriting {total_collected} total records to file...")
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(final_data, f, indent=4)
        print(f"Export complete! File saved to: {filename}")
    else:
        print("\nNo data retrieved from server to save.")

    # Return the rows list back to main() in case it needs to process them further
    if isinstance(final_data, dict):
        return final_data.get('rows', [])
    return final_data

def main():
    # 1. Setup & Authentication
    load_dotenv()  # Load environment variables from .env file if present
    ctd_ip = os.getenv("CTD_HOST")
    username = os.getenv("CTD_USERNAME")
    password = os.getenv("CTD_PASSWORD")
    
    headers = authenticate(ctd_ip, username, password)

    # 2. Select Test Mode
    print("Select an endpoint test option:")
    print(" [1] GET /ranger/assets (List & Paginate)")
    print(" [2] GET /ranger/assets/{resource_id} (Single Asset)")
    print(" [3] GET /ranger/assets_with_insights (List Assets with Insights)")
    print(" [4] GET /ranger/insights_summary (List Insights Summary) broken")
    print(" [5] GET /ranger/insight_details/{insight_name}")
    mode = input("Enter choice (1, 2, 3, 4, or 5): ").strip()

    if mode == "1":
        limit = get_target_limit()
        assets = fetch_paginated_assets(ctd_ip, headers, limit=limit)
        print("\n" + "=" * 60)
        print(json.dumps(assets, indent=4))
        print("=" * 60)
        print(f"FINAL OUTPUT ({len(assets)} items gathered from standard asset list):")

    elif mode == "2":
        resource_id = input("Enter the asset resource_id: ").strip()
        if not resource_id:
            print("Resource ID cannot be empty.")
            sys.exit(1)
        asset_data = fetch_single_asset(ctd_ip, headers, resource_id)
        if asset_data:
            print("\n" + "=" * 60)
            print(json.dumps(asset_data, indent=4))
            print("=" * 60)
            print(f"FINAL OUTPUT: Successfully fetched asset '{resource_id}'")
        else:
            print(f"Could not retrieve data for asset '{resource_id}'.")

    elif mode == "3":
        limit = get_target_limit()
        assets_with_insights = fetch_assets_with_insights(ctd_ip, headers, limit=limit)
        print("\n" + "=" * 60)
        print(json.dumps(assets_with_insights, indent=4))
        print("=" * 60)
        print(f"FINAL OUTPUT ({len(assets_with_insights)} items gathered from assets with insights):")

    elif mode == "4":
        limit = get_target_limit()
        insights_summary = fetch_paginated_insights_summary(ctd_ip, headers, limit=limit)
        
        print("\n" + "=" * 60)
        print(json.dumps(insights_summary, indent=4))
        print("=" * 60)
        print(f"FINAL OUTPUT ({len(insights_summary)} items gathered from insights summary list):")

    elif mode == "5":
        insight_name_input = input("Enter an insight name: ").strip()
        
        risky_assets = fetch_insight_details(ctd_ip, headers, insight_name=insight_name_input)
        
        print("\n" + "=" * 60)
        print(json.dumps(risky_assets, indent=4))
        print("=" * 60)
        print(f"FINAL OUTPUT ({len(risky_assets)} items gathered from {insight_name_input}):")
    
            
    else:
        print("Invalid menu choice. Exiting.")

if __name__ == "__main__":
    main()

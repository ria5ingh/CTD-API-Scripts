import csv
from unicodedata import name
import requests
import re
import time
import os
from dotenv import load_dotenv
from urllib.parse import quote

# ==========================================
# CONFIGURATION
# ==========================================
INPUT_CSV = 'winprogtest.csv'      
OUTPUT_CSV = 'full_cpe_list5.csv'    
NVD_API_URL = 'https://services.nvd.nist.gov/rest/json/cpes/2.0'

# Add your NVD API key here
load_dotenv()
API_KEY = os.getenv('NVD_KEY')
HEADERS = {
    'apiKey': API_KEY
}

# --- Row Limit ---
MAX_ROWS = int(input("Enter num of rows to process: ").strip())

# --- Mandatory Rate Limit Delay ---
SLEEP_DELAY = 0.6 

# ==========================================
# RULES & OVERRIDES
# ==========================================

# --- SUBSTRING OVERRIDES (The Fast Lane) ---
# If the cleaned program name CONTAINS these keys, it assigns the CPE without an API call.
SUBSTRING_OVERRIDES = {
    # Microsoft Suite
    "microsoft 365 apps": "cpe:2.3:a:microsoft:365_apps:*:*:*:*:*:*:*:*",
    "microsoft 365": "cpe:2.3:a:microsoft:365:*:*:*:*:*:*:*:*",
    "microsoft edge webview2": "cpe:2.3:a:microsoft:edge_chromium:*:*:*:*:*:*:*:*",
    "microsoft edge": "cpe:2.3:a:microsoft:edge:*:*:*:*:*:*:*:*",
    "microsoft teams": "cpe:2.3:a:microsoft:teams:*:*:*:*:*:*:*:*",
    
    # Windows SDKs/MS services
    "windows software development kit": "cpe:2.3:a:microsoft:windows_software_development_kit:*:*:*:*:*:*:*:*",
    "windows sdk": "cpe:2.3:a:microsoft:windows_software_development_kit:*:*:*:*:*:*:*:*",
    "universal crt": "NOT_FOUND",
    
    # Browsers
    "google chrome": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
    "mozilla firefox": "cpe:2.3:a:mozilla:firefox:*:*:*:*:*:*:*:*",
    "brave": "cpe:2.3:a:brave:brave:*:*:*:*:*:*:*:*",
    
    # Cisco
    "webex meetings server": "cpe:2.3:a:cisco:webex_meetings_server:*:*:*:*:*:*:*:*",
    "webex meetings": "cpe:2.3:a:cisco:webex_meetings:*:*:*:*:*:*:*:*",
    "webex": "cpe:2.3:a:cisco:webex:*:*:*:*:*:*:*:*",
    "packet tracer": "cpe:2.3:a:cisco:packet_tracer:*:*:*:*:*:*:*:*"
}

# --- VENDOR BLOCKLIST ---
# Programs from these vendors will be skipped, saving API calls.
IGNORED_VENDORS = [
    "hewlett packard",
    "hewlett-packard",
    "hp"
]

# PRE-COMPILED REGEX FOR MAXIMUM SPEED
# Used during the title matching phase to quickly strip valid trailing junk.
ALLOWED_JUNK_PATTERN = re.compile(
    r'\b\d+(?:\.\d+)+\b|'                
    r'\b\d+\b|'                          
    r'\(?\b(x86_64|x64_86|amd64|arm64|x64|x86|x32|win32|win64|64-?bit|32-?bit|all users|user)\b\)?|' 
    r'\b(v|version)\b|'                  
    r'[_\-\.\(\)\s]+'                    
)

# ==========================================
# FUNCTIONS
# ==========================================

def clean_program_name(name):
    """
    Cleans messy naming conventions by truncating at common delimiters, 
    then stripping locales, architectures, and appended build strings.
    """
    name = name.split(' - ')[0]    
    name = re.sub(r'(?i)\b[a-z]{2}-[a-z]{2}\b', '', name) 

    arch_pattern = r'(?i)\b(x86_64|x64_86|amd64|arm64|x64|x86|x32|win32|win64|64-?bit|32-?bit|all users|user)\b'
    name = re.sub(arch_pattern, '', name)
    
    version_pattern = r'\b\d+(?:\.\d+)+\b'
    name = re.sub(version_pattern, '', name)
    
    filler_pattern = r'(?i)\b(for)\b'
    name = re.sub(filler_pattern, '', name)

    name = re.sub(r'\(\s*\)', '', name)
    cleaned_name = re.sub(r'\s+', ' ', name).strip()
    cleaned_name = re.sub(r'^-|-$', '', cleaned_name).strip()
    
    return cleaned_name

def is_valid_title_match(keyword, nvd_title):
    """
    Highly optimized title evaluation. Checks if the NVD title starts with 
    our keyword and ONLY contains valid trailing junk.
    """
    # Splits on standard hyphens (-), en-dashes (–), and em-dashes (—)
    nvd_title = re.split(r'\s+[-–—]\s+', nvd_title, maxsplit=1)[0].strip()

    keyword_lower = keyword.lower()
    title_lower = nvd_title.lower()
    
    # 1. Fast fail: Must start exactly with our base product name
    if not title_lower.startswith(keyword_lower):
        return False
        
    # 2. Grab the remainder
    remainder = title_lower[len(keyword_lower):]
    
    # Fast pass: If there is nothing trailing, it's a perfect exact match
    if not remainder:
        return True 
        
    # 3. Strip all allowed junk in a single, C-optimized pass
    remainder = ALLOWED_JUNK_PATTERN.sub('', remainder)
    
    # 4. If any letters are left over, it's an invalid match
    return len(remainder) == 0

def generalize_cpe(raw_cpe):
    """
    Takes a specific CPE and returns a version-agnostic CPE 
    (e.g., cpe:2.3:a:7-zip:7-zip:*:*:*:*:*:*:*:*)
    """
    parts = raw_cpe.split(':')
    
    if len(parts) >= 5 and parts[0] == 'cpe' and parts[1] == '2.3':
        base_cpe = ':'.join(parts[:5])
        generic_cpe = f"{base_cpe}:*:*:*:*:*:*:*:*"
        return generic_cpe
        
    return raw_cpe

def query_nvd_for_cpe(keyword):
    """
    Checks the substring overrides first. If no matches are found, queries the API.
    """
    if not keyword:
        return None
        
    keyword_lower = keyword.lower()

    # --- FAST-PATH: Check Substring Overrides ---
    for term, cpe in SUBSTRING_OVERRIDES.items():
        if term in keyword_lower:
            if cpe == "NOT_FOUND":
                print("[Override Applied: NOT_FOUND]", end=" ")
                return None
            print("[Override Applied]", end=" ")
            return cpe

    # --- STANDARD PATH: Query the API using heuristic logic ---
    encoded_keyword = quote(keyword)
    url = f"{NVD_API_URL}?keywordSearch={encoded_keyword}"
    
    try:
        response = requests.get(url, headers=HEADERS)
        response.raise_for_status() 
        data = response.json()
        
        if data.get('totalResults', 0) > 0 and 'products' in data:
            products = data['products']
            
            # find a valid title match
            for product in products:
                cpe_data = product['cpe']
                for title_info in cpe_data.get('titles', []):
                    title = title_info.get('title', '')
                    
                    if is_valid_title_match(keyword, title):
                        return generalize_cpe(cpe_data['cpeName'])
            
            # Safety Fallback
            return generalize_cpe(products[0]['cpe']['cpeName'])
            
    except requests.exceptions.HTTPError as e:
        print(f" [!] Blocked by NVD: {e.response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f" [!] Network Error: {e}")

    return None

def main():
    start_time = time.time()
    
    # 1. Initialize the output file with the 5-column headers
    with open(OUTPUT_CSV, mode='w', newline='', encoding='utf-8') as out_file:
        writer = csv.writer(out_file)
        writer.writerow(['program', 'vendor', 'version', 'cleaned name', 'cpe_name'])

    print("Starting NVD CPE enumeration...")
    
    with open(INPUT_CSV, mode='r', encoding='utf-8-sig') as in_file:
        reader = csv.DictReader(in_file)
        
        if not reader.fieldnames or 'program' not in [h.strip().lower() for h in reader.fieldnames if h]:
            print("\n[CRITICAL ERROR] Could not find a column named 'program' in your CSV!")
            return

        for count, row in enumerate(reader):
            
            if MAX_ROWS is not None and count >= MAX_ROWS:
                print(f"\n[INFO] Reached the specified limit of {MAX_ROWS} rows. Stopping.")
                break
                
            raw_program = ""
            raw_vendor = ""
            raw_version = ""
            
            # 2. Extract program, vendor, AND version from the raw CSV
            for key in row.keys():
                clean_key = key.strip().lower() if key else ""
                if clean_key == 'program':
                    raw_program = row[key]
                elif clean_key == 'vendor':
                    raw_vendor = row[key]
                elif clean_key == 'version':
                    raw_version = row[key]
            
            if not raw_program:
                continue
                
            cleaned_name = clean_program_name(raw_program)
            
            # --- Write skipped vendors to the CSV with all 5 fields ---
            if raw_vendor and raw_vendor.strip().lower() in IGNORED_VENDORS:
                print(f"Skipping: {cleaned_name} (Blocked Vendor: {raw_vendor})")
                with open(OUTPUT_CSV, mode='a', newline='', encoding='utf-8') as out_file:
                    writer = csv.writer(out_file)
                    writer.writerow([raw_program, raw_vendor, raw_version, cleaned_name, 'NOT_FOUND (Skipped)'])
                continue
            
            print(f"Searching: {cleaned_name} ...", end=" ")
            
            cpe_name = query_nvd_for_cpe(cleaned_name)
            
            # --- Write API results to the CSV with all 5 fields ---
            with open(OUTPUT_CSV, mode='a', newline='', encoding='utf-8') as out_file:
                writer = csv.writer(out_file)
                if cpe_name:
                    writer.writerow([raw_program, raw_vendor, raw_version, cleaned_name, cpe_name])
                    print(f"Found Base: {cpe_name}")
                else:
                    writer.writerow([raw_program, raw_vendor, raw_version, cleaned_name, 'NOT_FOUND'])
                    print("NOT FOUND")
            
            # MANDATORY DELAY
            time.sleep(SLEEP_DELAY)

    #print results   
    print("\nProcess complete. Results saved to", OUTPUT_CSV)

    #print time
    end_time = time.time()
    total_seconds = end_time - start_time
    minutes, seconds = divmod(total_seconds, 60)
    print(f"Total Execution Time: {int(minutes)} minutes and {seconds:.2f} seconds")

if __name__ == "__main__":
    main()
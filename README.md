# CTD API Scripts

This is a collection of Python scripts to automate commonly requested or custom tasks using the CTD API. Running these scripts will query your CTD instance and generate one or more CSV files detailing specific relationships as per the script.

### Prerequisites

- **python 3.14.5 or later**
- pip install -r requirements.txt
- request API key for NVD, create a .env file and enter the key as NVD_KEY = "your key"

### Current Scripts
1. **`Assets_Per_CVE.py`**: generates two CSV files:
    - **`cve_ids_list.csv`**: Lists confirmed CVEs along with # of assets corresponding to each CVE.
    - **`assets_per_cve_list.csv`**: Lists all individual assets per confirmed CVE.

2. **`CVEs_Per_Asset.py`**: generates two CSV files:

    - **`assets_cve_counts_list.csv`**: Lists all assets along with # of confirmed CVEs per asset.
    - **`cves_per_asset_list.csv`**: Lists all confirmed CVEs per asset.

3. **`Get_Edge_Host.py`**: example/helper script that identifies the Windows 10/11 Edge Host from a CTD instance, given login credentials. Prints output to terminal.

4. **`Get_Edge_Progs.py`**: Identifies Windows 10/11 Edge Host (using the same logic from Get_Edge_Host.py) and generates a CSV file labeled **`windows_programs_list.csv`**, which lists the `[program, vendor, version]` of all installed programs.

5. **`cpenameV2.py`**: generates a CSV file that lists all programs AND each program's "cpeName" (if it exists).
    - the "cpeName" is similar to a unique identifier given to programs in the NVD database, typically in the format `cpe:2.3:a:{vendor}:{program}:{version}:*:*:*:*:*:*:*`, where each `*` is a field corresponding to edition, target software/hardware, etc.
    - given an input csv file with a list of programs in the format `[program, vendor, version]`, this script standardizes all program names and uses the "cleaned" program name to query the NVD database for the matching cpeName string. 

### Instructions
Running the scripts will prompt for your hostname or IP, username, and password for your CTD instance. Once inputed, the scripts will query the API and create the corresponding CSVs in your local directory. 

### Future Development
- CVEs for 3rd-party Windows Programs script (integrate with NVD)
- CVEs for Linux OS script

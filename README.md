# CTD API Scripts

This is a collection of Python scripts to automate commonly requested or custom tasks using the CTD API. Running these scripts will query your CTD instance and generate one or more CSV files detailing specific relationships as per the script.

### Prerequisites

- **python 3.14.5 or later**
- pip install -r requirements.txt
- request API key for NVD, create a .env file and enter the key as NVD_KEY = "your key"

### Current Scripts
1. **`Assets_Per_CVE.py`**: generates two CSV files given the hostname/IP of the CTD instance and credentials. 
    - **`cve_ids_list.csv`**: Lists confirmed CVEs along with # of assets corresponding to each CVE.
    - **`assets_per_cve_list.csv`**: Lists all individual assets per confirmed CVE.

2. **`CVEs_Per_Asset.py`**: generates two CSV files given the hostname/IP of the CTD instance and credentials. 
    - **`assets_cve_counts_list.csv`**: Lists all assets along with # of confirmed CVEs per asset.
    - **`cves_per_asset_list.csv`**: Lists all confirmed CVEs per asset.

3. **`Get_Edge_Host.py`**: example/helper script that identifies the Windows 10/11 Edge Host from a CTD instance, given the hostname/IP and credentials. Prints output to terminal.

4. **`Get_Edge_Progs.py`**: Identifies Windows 10/11 Edge Host (using the same logic from Get_Edge_Host.py) and generates a CSV file labeled **`windows_programs_list.csv`**, with columns `[program, vendor, version, in_ctd]`

    How to read output:
    * `program, vendor, version`: describes the program, vendor, and version for each program
    * `in_ctd`: "**yes**" if the program's KEVs are already tracked by CTD, (the last of tracked vendor and programs are in `cve_program_matcher_cut.csv`). "**no**" if the program is *not* natively tracked by CTD. 

5. **`cpenameV5.py`**: generates a CSV file that lists all programs AND each program's "cpeName" (if it exists).
    - The "**cpeName**" is a unique identifier given to programs in the NVD database, typically formatted as `cpe:2.3:a:{vendor}:{program}:{version}:*:*:*:*:*:*:*`, where each `*` represents fields like edition, target software/hardware, etc.
    - Given an input csv file with a list of programs in the format `[program, vendor, version, in_ctd]`, this script standardizes all program names, using "cleaned" program name to query the NVD database for the matching cpeName string. It matches results with strict substring matching first, and token-based matching as a fallback. 
    - Outputs a csv file with columns: `[program, vendor, version, in_ctd, cleaned_name, cpe_name, confidence]`

    How to read output:

    * `program, vendor, version, in_ctd`: these columns are the same as the input csv
    * `cleaned_name`: the standardized program name used to query the NVD CPE database
    * `cpe_name`: the generalized base cpeName of the program, or `NOT_FOUND` if the program was not in the NVD CPE database.
    * `confidence`: describes the certainty of a cpeName match.
        * "**F**" (Full): A strict title match was found and vetted. Think of this as a highly confident match.
        * "**P**" (Potential): A token-based match was found (all tokens appear, but not in a continuous string). This is not a confirmed full match. 
        * "**O**" (Override): The program search was overridden by a pre-mapped CPE string. (Used for common programs to reduce API calls. ie, Microsoft Office programs, common browsers like Chrome, etc). If a program title *contains* a string that is pre-mapped, it will automatically be overridden, hence, the match may not be 100% guaranteed.
        * "**N**" (N/A): no valid cpeName matches were found.

6. **`cve_matchv4.py`**: Given an input CSV file containing valid CPE names and versions (the output from `cpenameV5.py`), this script queries the NVD API to find CVEs that match the CPE's version and software (Windows OS), generating a csv file with all the CVEs found. NOTE: this script finds CVEs for applications only applicable to Windows environments. It does not return CVEs for programs that also require other specific hardware configurations. 
    - User is prompted for the input/output filenames, an optional limit on how many CVEs to fetch per program, and whether to strictly filter for only Known Exploited Vulnerabilities (KEVs).
    - Outputs a csv file with columns: `[Program, Version, Queried_CPE, Confidence, CVE, CVSS_Version, Base_Score, Base_Severity, CISA_KEV]`

    How to read output:

    * `Program, Version, Queried_CPE, Confidence`: These columns are carried over directly from the input CSV to maintain tracking.
    * `CVE`: The unique identifier for the specific vulnerability (e.g., CVE-2024-12345).
    * `CVSS_Version`: The version of the Common Vulnerability Scoring System used for the primary metric. The script prioritizes the newest available scoring system (e.g., 4.0, 3.1, 3.0, 2.0).
    * `Base_Score`: The numerical CVSS severity score of the vulnerability, ranging from 0.0 to 10.0.
    * `Base_Severity`: The qualitative severity rating (e.g., LOW, MEDIUM, HIGH, CRITICAL).
    * `CISA_KEV`: The official CISA vulnerability name if the CVE is currently listed on the CISA Known Exploited Vulnerabilities catalog. If it is not on the catalog, this will read "N/A".

    
### Instructions
Running the scripts will prompt for your hostname or IP, username, and password for your CTD instance. Once inputed, the scripts will query the API and create the corresponding CSVs in your local directory. 

### Future Development
- ~~CVEs for 3rd-party Windows Programs script (integrate with NVD)~~
- CVEs for Linux OS script

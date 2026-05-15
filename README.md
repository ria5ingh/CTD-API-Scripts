# CTD API Scripts

This is a collection of Python scripts to automate commonly requested or custom tasks using the CTD API. Running these scripts will query your CTD instance and generate one or more CSV files detailing specific relationships as per the script.

### Prerequisites

- **python 3.14.5 or later**
- install requirements.txt 

### Current Scripts
1. **Assets-Per-CVE.py**: generates two CSV files:
    - **cve_ids_list.csv**: Lists confirmed CVEs along with # of assets corresponding to each CVE.
    - **assets_per_cve_list.csv**: Lists all individual assets per confirmed CVE.

2. **CVEs-Per-Asset.py**: generates two CSV files:

    - **assets_cve_counts_list.csv**: Lists all assets along with # of confirmed CVEs per asset.
    - **cves_per_asset_list.csv**: Lists all confirmed CVEs per asset.

### Instructions
Running the scripts will prompt for your hostname or IP, username, and password for your CTD instance. Once inputed, the scripts will query the API and create the corresponding CSVs in your local directory. 

### Future Development
- CVEs for 3rd-party Windows Programs script (integrate with NVD)
- CVEs for Linux OS script

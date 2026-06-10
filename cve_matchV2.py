import csv
import requests
import time
import os
from dotenv import load_dotenv

# CONFIGURATION
INPUT_CSV = input("Enter input CSV file name: ").strip()
OUTPUT_CSV = input("Enter output CSV file name: ").strip()
NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

load_dotenv()

API_KEY = os.getenv("NVD_KEY")

HEADERS = {}
if API_KEY:
    HEADERS["apiKey"] = API_KEY

MAX_CVES_PER_PROGRAM = 100
SLEEP_DELAY = 0.6

#FUNCTIONS
def build_versioned_cpe(cpe_name, version):
    parts = cpe_name.split(":")

    if len(parts) < 13:
        raise ValueError(f"Invalid CPE: {cpe_name}")
    parts[5] = version

    return ":".join(parts)


def query_cves(cpe_string):
    response = requests.get(
        NVD_CVE_API_URL,
        params={"virtualMatchString": cpe_string},
        headers=HEADERS,
        timeout=30
    )

    response.raise_for_status()
    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])

    cves = []

    for vuln in vulnerabilities[:MAX_CVES_PER_PROGRAM]:
        cve_id = vuln.get("cve", {}).get("id")
        if cve_id:
            cves.append(cve_id)

    return cves


#MAIN
def main():

    start_time = time.time()

    duplicate_count = 0

    total_programs = 0
    cpe_matched_programs = 0
    unique_cpe_queries = 0
    total_found_cves = 0

    previous_query_cpe = None

    print("\nStarting CVE lookup...\n")

    #create output file
    with open(OUTPUT_CSV,"w",newline="",encoding="utf-8") as outfile:
        writer = csv.writer(outfile)
        writer.writerow(["Program","Version","Queried_CPE","Confirmed","CVE"])

    #process input
    with open(INPUT_CSV,"r",encoding="utf-8-sig") as infile:
        reader = csv.DictReader(infile)
        for row in reader:
            total_programs += 1

            program = row.get("program", "").strip()
            version = row.get("version", "").strip()
            cpe_name = row.get("cpe_name", "").strip()
            confirmed = row.get("confirmed", "").strip()

            if not cpe_name or cpe_name.upper() == "NOT_FOUND":
                continue

            cpe_matched_programs += 1

            if not version:
                continue

            try:
                query_cpe = build_versioned_cpe(cpe_name, version)

                # DUPLICATE CHECK
                if query_cpe == previous_query_cpe:
                    print( f"  -> Duplicate CPE Skipped: "f"'{program}'")
                    duplicate_count += 1
                    continue

                print(f"Querying: {program} " f"(v{version})")
                cves = query_cves(query_cpe)
                unique_cpe_queries += 1
                total_found_cves += len(cves)

                print(f"  -> Found {len(cves)} CVEs")

                with open(OUTPUT_CSV,"a",newline="",encoding="utf-8") as outfile:
                    writer = csv.writer(outfile)
                    if cves:
                        for cve in cves:
                            writer.writerow([program,version,query_cpe,confirmed,cve])
                
                #save for duplicate check
                previous_query_cpe = query_cpe

            except Exception as e:
                print(f"  [ERROR] {program}: {e}")
            time.sleep(SLEEP_DELAY)

    elapsed = time.time() - start_time
    minutes, seconds = divmod(elapsed, 60)

    print("\n===================================")
    print(f"Results saved to: {OUTPUT_CSV}")
    print(f"Total Programs: {total_programs}")
    print(f"CPE-Matched Programs: {cpe_matched_programs}")
    print(f"Unique CPEs Queried: {unique_cpe_queries}")
    print(f"Duplicate CPEs Skipped: {duplicate_count}")
    print(f"Total CVEs Found: {total_found_cves}")
    print(f"\nRuntime: {int(minutes)}m "f"{seconds:.2f}s")


if __name__ == "__main__":
    main()
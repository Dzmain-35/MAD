import hashlib
import os
import sys
import pyperclip
import traceback
from virus_total_apis import PublicApi as VirusTotalPublicApi

def fetch_and_print_file_details(api_key, file_hash):
    try:
        vt = VirusTotalPublicApi(api_key)
        
        # Fetch file report
        file_report = vt.get_file_report(file_hash)
        
        if file_report['response_code'] != 200:
            print("Error fetching file report.")
            sys.exit(1)
        
        file_info = file_report.get('results', {})

        # ✅ Moved up — print first, before any exit()
        positives = file_info.get('positives', 0)
        total = file_info.get('total', '?')
        print(f"VT Detection: {positives}/{total}")

        if 'scans' not in file_info:
            print("No scan results available for this file hash.")
            sys.exit(1)

        print("Top 10 Malware Family Names:")

        print("----------------------------------------------------------------------------------------------------------------------")
        count = 0
        for engine, result in file_info['scans'].items():
            if result.get('result') is not None:
                print(f"Malware Family: {result['result']}")
                print("----------------------------------------------------------------------------------------------------------------------")
                count += 1
                if count >= 10:
                    break
        
    except Exception as e:
        print("An error occurred:")
        traceback.print_exc()
        sys.exit(1)

# Replace with your actual API key
api_key = "93aa3b4a6ba88ba96734df3e73147f89ecfd63164f3eacd240c1ff6e592d9d49"

try:
    if len(sys.argv) < 2:
        print("Error: Please provide the file path as a command line argument.")
        sys.exit(1)

    fn = sys.argv[1]

    with open(fn, 'rb') as f:
        bytes = f.read()
        md5 = hashlib.md5(bytes).hexdigest()

    file_name = os.path.basename(fn)
    fetch_and_print_file_details(api_key, md5)

except KeyboardInterrupt:
    print("\nScript interrupted by user.")
    sys.exit(0)

except FileNotFoundError:
    print(f"Error: File '{fn}' not found.")
    sys.exit(1)

except Exception as e:
    print("An unexpected error occurred during script execution.")
    print(str(e))
    sys.exit(1)

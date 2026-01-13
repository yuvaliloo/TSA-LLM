import requests
import zipfile
import csv
from io import BytesIO
import os
import pyzipper
import sys

# CONFIG
SAVE_DIR = "./data/malware"
# Try the 'recent' list again
CSV_URL = "https://bazaar.abuse.ch/export/csv/recent/"
API_URL = "https://mb-api.abuse.ch/api/v1/"
PASSWORD = b"infected"
TARGET_COUNT = 500

def get_csv_candidates():
    print(f"[*] Downloading CSV list from: {CSV_URL}")
    
    try:
        # 1. Download content
        r = requests.get(CSV_URL, stream=True, timeout=60)
        content = r.content
        
        # 2. DEBUG: Check if it's actually a zip
        # Zip files ALWAYS start with "PK" (bytes 50 4B)
        if not content.startswith(b'PK'):
            print("\n[!] CRITICAL ERROR: The server did NOT return a zip file.")
            print(f"    Server Status Code: {r.status_code}")
            print(f"    Response Length: {len(content)} bytes")
            print("--- SERVER RESPONSE (First 200 chars) ---")
            print(content[:200].decode('utf-8', errors='ignore'))
            print("-----------------------------------------")
            return []

        # 3. If valid, process it
        print("    [+] Valid Zip header found. Extraction starting...")
        candidates = []
        
        with zipfile.ZipFile(BytesIO(content)) as zf:
            csv_filename = zf.namelist()[0]
            with zf.open(csv_filename) as f:
                lines = f.read().decode('utf-8', errors='ignore').splitlines()
                reader = csv.reader(lines)
                
                for row in reader:
                    if not row or row[0].startswith('#'): continue
                    if len(row) < 5: continue
                    
                    sha256 = row[1]
                    file_type = row[4]
                    file_name = row[5]
                    
                    # Filter for Office Docs
                    if file_type in ['docm', 'xlsm', 'pptm', 'docx', 'xlsx'] or \
                       any(file_name.lower().endswith(x) for x in ['.docm', '.xlsm']):
                        candidates.append((sha256, file_name))
                        
        print(f"[*] Success: Found {len(candidates)} candidates in the list.")
        return candidates

    except Exception as e:
        print(f"[-] Error downloading CSV: {e}")
        return []

def download_file(sha256, filename):
    final_path = os.path.join(SAVE_DIR, filename)
    if os.path.exists(final_path): return False
    
    payload = {"query": "get_file", "sha256_hash": sha256}
    try:
        r = requests.post(API_URL, data=payload, stream=True, timeout=30)
        
        # Check if API returned an error message instead of a zip
        if b"query_status" in r.content[:100] and b"file_not_found" in r.content:
            return False

        temp_zip = os.path.join(SAVE_DIR, "temp.zip")
        with open(temp_zip, 'wb') as f:
            for chunk in r.iter_content(8192): f.write(chunk)
            
        try:
            with pyzipper.AESZipFile(temp_zip) as zf:
                zf.setpassword(PASSWORD)
                first = zf.namelist()[0]
                with zf.open(first) as src, open(final_path, 'wb') as dst:
                    dst.write(src.read())
            print(f"    [+] Saved: {filename}")
            return True
        except:
            return False
        finally:
            if os.path.exists(temp_zip): os.remove(temp_zip)
    except:
        return False

def run():
    if not os.path.exists(SAVE_DIR): os.makedirs(SAVE_DIR)
    
    candidates = get_csv_candidates()
    
    if not candidates:
        print("[-] FAILED to get file list. The server might be blocking the CSV download.")
        return

    count = len(os.listdir(SAVE_DIR))
    print(f"[*] Downloading samples (Target: {TARGET_COUNT})...")
    
    for sha256, name in candidates:
        if count >= TARGET_COUNT: break
        if download_file(sha256, name):
            count += 1

if __name__ == "__main__":
    run()
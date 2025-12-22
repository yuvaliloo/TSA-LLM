import requests
import pyzipper
import os
import io
import csv
import sys
from dotenv import load_dotenv

load_dotenv()

# --- CONFIGURATION ---
API_URL = "https://mb-api.abuse.ch/api/v1/"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
MALWARE_DIR = os.path.join(DATA_DIR, "malware")
LABELS_FILE = os.path.join(DATA_DIR, "labels.csv")

PASSWORD = b"infected"
API_KEY = os.environ.get("MB_API_KEY")

if not API_KEY:
    print("Error: MB_API_KEY is missing in .env")
    sys.exit(1)

HEADERS = { "Auth-Key": API_KEY }

def is_zip_header(filepath):
    """Checks for the 'PK' magic bytes"""
    try:
        with open(filepath, 'rb') as f:
            return f.read(2) == b'PK'
    except:
        return False

def init_setup():
    if not os.path.exists(MALWARE_DIR):
        os.makedirs(MALWARE_DIR)
    
    if not os.path.exists(LABELS_FILE):
        with open(LABELS_FILE, 'w', newline='') as f:
            csv.writer(f).writerow(["sha256", "filename", "label", "source"])

def log_sample(sha256, filename, label, source):
    # Check for duplicates
    if os.path.exists(LABELS_FILE):
        with open(LABELS_FILE, 'r') as f:
            if sha256 in f.read(): return

    with open(LABELS_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([sha256, filename, label, source])

def fetch_samples(file_type, target_count=10):
    print(f"[+] Searching for VALID {file_type} (Target: {target_count})...")
    
    # We fetch a larger batch because we might discard invalid ones
    payload = {
        "query": "get_file_type",
        "file_type": file_type,
        "limit": "50" 
    }
    
    try:
        response = requests.post(API_URL, data=payload, headers=HEADERS)
        data = response.json()
        
        if data["query_status"] != "ok":
            print(f"[-] API Error: {data.get('query_status')}")
            return

        collected = 0
        for sample in data["data"]:
            if collected >= target_count:
                break

            sha256 = sample["sha256_hash"]
            real_filename = sample['file_name'] # This is the name we want!
            
            # Skip if we already have it
            final_path = os.path.join(MALWARE_DIR, real_filename)
            if os.path.exists(final_path):
                print(f"    [Exists] {real_filename}")
                collected += 1
                continue

            # Download
            dl_payload = {"query": "get_file", "sha256_hash": sha256}
            dl_resp = requests.post(API_URL, data=dl_payload, headers=HEADERS)
            
            try:
                # 1. Extract to a temp buffer
                with pyzipper.AESZipFile(io.BytesIO(dl_resp.content)) as zf:
                    zf.setpassword(PASSWORD)
                    
                    # MalwareBazaar usually puts one file inside the zip
                    internal_name = zf.namelist()[0]
                    
                    # Extract it to disk
                    zf.extract(internal_name, MALWARE_DIR)
                    
                    # 2. RENAME IT IMMEDIATELY
                    # The file is currently on disk as `internal_name` (often the hash)
                    temp_path = os.path.join(MALWARE_DIR, internal_name)
                    
                    # Rename to the human-readable name from the API
                    os.rename(temp_path, final_path)
                
                # 3. Validation Check
                if is_zip_header(final_path):
                    log_sample(sha256, real_filename, "Malicious", "MalwareBazaar")
                    print(f"    [Saved] {real_filename}")
                    collected += 1
                else:
                    # Invalid format (Binary OLE), delete it
                    print(f"    [Skipped] {real_filename} (Binary Format)")
                    os.remove(final_path)

            except Exception as e:
                print(f"    [Error] Failed to process {real_filename}: {e}")

    except Exception as e:
        print(f"[-] Network Error: {e}")

if __name__ == "__main__":
    init_setup()
    fetch_samples("docx", target_count=10)
    fetch_samples("xlsx", target_count=10)
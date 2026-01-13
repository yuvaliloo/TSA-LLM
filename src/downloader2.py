import requests
import os
import pyzipper
import time
import io  # <--- Moved to top (Critical for BytesIO)
from dotenv import load_dotenv

load_dotenv()

# CONFIG
API_KEY = os.environ.get("MB_API_KEY") 
TARGET_DIR = "../data/malware"
TAGS_TO_HUNT = ["docm", "xlsm", "docx", "pptm", "pptx", "xlsx", "Emotet", "Qakbot", "IcedID"] 

# --- SAFEGUARD: Check Key ---
if not API_KEY:
    print("[-] WARNING: MB_API_KEY is not set. You might get 'Unauthorized' errors.")
    # You can temporarily hardcode it here if .env fails:
    # API_KEY = "YOUR_KEY_HERE"

def download_file(sha256_hash, api_key):
    data = {'query': 'get_file', 'sha256_hash': sha256_hash}
    
    # FIX 1: Add Headers here too!
    headers = {'API-KEY': api_key} 
    
    try:
        response = requests.post('https://mb-api.abuse.ch/api/v1/', data=data, headers=headers, timeout=15)
        
        if 'file_not_found' in response.text:
            return None
        
        # Check for Unauthorized/Error in download specifically
        if 'query_status' in response.json() and response.json()['query_status'] != 'ok':
             print(f"    [-] Download Error: {response.json()['query_status']}")
             return None
             
        return response.content
    except Exception as e:
        print(f"    [-] Network error: {e}")
        return None

def run():
    if not os.path.exists(TARGET_DIR):
        os.makedirs(TARGET_DIR)

    total_downloaded = 0

    print(f"[*] Starting Targeted Hunt for: {TAGS_TO_HUNT}")

    for tag in TAGS_TO_HUNT:
        print(f"[*] Searching for tag: {tag}...")
        
        data = {'query': 'get_taginfo', 'tag': tag, 'limit': 1000}
        headers = {'API-KEY': API_KEY}
        
        try:
            response = requests.post('https://mb-api.abuse.ch/api/v1/', data=data, headers=headers, timeout=10)
            json_response = response.json()
        except Exception as e:
            print(f"[-] Connection failed for {tag}: {e}")
            continue

        if 'query_status' not in json_response:
            print(f"[-] CRITICAL API ERROR: Key 'query_status' missing.")
            print(f"    Raw Response: {json_response}")
            continue

        if json_response['query_status'] != 'ok':
            print(f"    [-] No results for {tag} (Status: {json_response['query_status']})")
            continue
            
        files = json_response['data']
        print(f"    [+] Found {len(files)} potential candidates for '{tag}'. Downloading...")

        for file_info in files:
            sha256 = file_info['sha256_hash']
            file_type = file_info.get('file_type', '')
            
            # Double check it's actually an office file
            if file_type not in ['docm', 'xlsm', 'docx', 'xlsx', 'pptm', 'ppt']:
                continue

            expected_filename = sha256 + "." + file_type
            if os.path.exists(os.path.join(TARGET_DIR, expected_filename)):
                print(f"    [.] Skipping {sha256[:8]} (Already exists)")
                continue

            # FIX 2: Pass the API Key to the download function
            content = download_file(sha256, API_KEY)
            
            if content:
                try:
                    with pyzipper.AESZipFile(io.BytesIO(content)) as zf:
                        zf.setpassword(b"infected")
                        for member in zf.namelist():
                            with zf.open(member) as f_in:
                                file_data = f_in.read()
                                
                                final_path = os.path.join(TARGET_DIR, expected_filename)
                                with open(final_path, 'wb') as f_out:
                                    f_out.write(file_data)
                                
                                total_downloaded += 1
                                print(f"    [+] DOWNLOADED: {expected_filename}")
                                
                except Exception as e:
                    print(f"    [-] Unzip error: {e}")

            time.sleep(1) 

            if total_downloaded >= 300:
                print("\n[!!!] GOAL REACHED! You have downloaded 300 new files.")
                return

    print(f"[*] Hunt complete. Total new files: {total_downloaded}")

if __name__ == "__main__":
    run()
import requests
import os
import csv
import hashlib
import time

# CONFIGURATION
# GovDocs1 Subset 000 (The "Gold Standard" for benign research files)
URL = "https://downloads.digitalcorpora.org/corpora/files/govdocs1/zipfiles/000.zip"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# 2. Go up one level to the root (LLM-TSA)
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)

# 3. Point to the data folder
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
BENIGN_DIR = os.path.join(DATA_DIR, "benign")
LABELS_FILE = os.path.join(DATA_DIR, "labels.csv")

SOURCES = [
    {
        "type": "docx", 
        "url": "https://api.github.com/repos/apache/poi/contents/test-data/document"
    },
    {
        "type": "xlsx", 
        "url": "https://api.github.com/repos/apache/poi/contents/test-data/spreadsheet"
    },
    {
        "type": "pptx", 
        "url": "https://api.github.com/repos/apache/poi/contents/test-data/slideshow"
    }
]

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def log_to_csv(filename, sha256):
    # Ensure CSV exists
    if not os.path.exists(LABELS_FILE):
        with open(LABELS_FILE, 'w', newline='') as f:
            csv.writer(f).writerow(["sha256", "filename", "label", "source"])

    # Check for duplicates (simple check)
    with open(LABELS_FILE, 'r') as f:
        if sha256 in f.read():
            return

    with open(LABELS_FILE, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([sha256, filename, "Benign", "ApachePOI"])

def download_benign():
    if not os.path.exists(BENIGN_DIR):
        os.makedirs(BENIGN_DIR)

    print(f"[+] Starting Download from Apache POI Test Data...")
    
    total_downloaded = 0
    
    for source in SOURCES:
        print(f"    Scanning {source['type']} repository...")
        try:
            # 1. Get File List from GitHub API
            resp = requests.get(source['url'])
            if resp.status_code != 200:
                print(f"    [-] Failed to list files: {resp.status_code}")
                continue
                
            files = resp.json()
            
            # 2. Iterate and Download
            for f_item in files:
                name = f_item['name']
                download_url = f_item.get('download_url')
                
                # Filter: Only grab the relevant extension (ignore .xml or .txt sidecars)
                if not name.endswith(f".{source['type']}") and not name.endswith(source['type'].replace('x', 'm')):
                    continue
                
                if not download_url:
                    continue

                target_path = os.path.join(BENIGN_DIR, name)
                
                # Skip if we already have it
                if os.path.exists(target_path):
                    continue
                
                print(f"      Downloading {name}...")
                
                # Download File
                file_resp = requests.get(download_url)
                with open(target_path, "wb") as f_out:
                    f_out.write(file_resp.content)
                
                # Log it
                file_hash = calculate_sha256(target_path)
                log_to_csv(name, file_hash)
                
                total_downloaded += 1
                
                # Limit to 20 files per type to avoid huge downloads (remove break for full set)
                if total_downloaded % 20 == 0:
                     print("      (Paused for 1s to be nice to GitHub API...)")
                     time.sleep(1)

        except Exception as e:
            print(f"    [-] Error processing {source['type']}: {e}")

    print(f"\n[+] Finished. Total benign files added: {total_downloaded}")

if __name__ == "__main__":
    download_benign()
import os
import csv

# 1. Setup Paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
LABELS_FILE = os.path.join(DATA_DIR, "labels.csv")

DIRS = {
    "Malicious": os.path.join(DATA_DIR, "malware"),
    "Benign": os.path.join(DATA_DIR, "benign")
}

def check_paths():
    print(f"--- PATH DEBUGGER ---")
    print(f"Project Root: {PROJECT_ROOT}")
    print(f"Data Dir:     {DATA_DIR}")
    print(f"Labels CSV:   {LABELS_FILE}")
    
    # 2. Check if folders exist
    for label, folder in DIRS.items():
        exists = "✅" if os.path.exists(folder) else "❌"
        print(f"Folder ({label}): {exists} {folder}")
        if os.path.exists(folder):
            files = os.listdir(folder)
            print(f"   -> Contains {len(files)} files. First 3: {files[:3]}")

    print("-" * 30)

    # 3. Simulate the Build Process
    if not os.path.exists(LABELS_FILE):
        print("❌ CRITICAL: labels.csv is missing!")
        return

    with open(LABELS_FILE, 'r') as f:
        reader = csv.DictReader(f)
        
        # Check header
        print(f"CSV Headers: {reader.fieldnames}")
        if 'filename' not in reader.fieldnames:
            print("❌ CRITICAL: 'filename' column missing in CSV.")
            return

        print("\n--- Testing First 5 Rows ---")
        for i, row in enumerate(reader):
            if i >= 5: break
            
            filename = row['filename']
            label = row['label']
            folder = DIRS.get(label, DATA_DIR) # Default to data root if label weird
            
            # Construct the path exactly like build_dataset.py does
            expected_path = os.path.join(folder, filename)
            
            # Check reality
            if os.path.exists(expected_path):
                print(f"✅ Found: {filename}")
            else:
                print(f"❌ MISSING: {filename}")
                print(f"   -> Script looked at: {expected_path}")
                
                # Try to find where it actually is
                actual_loc = "Unknown"
                if os.path.exists(os.path.join(DATA_DIR, filename)):
                    actual_loc = "Root /data folder"
                elif os.path.exists(os.path.join(DATA_DIR, "malware", filename)):
                    actual_loc = "/data/malware"
                elif os.path.exists(os.path.join(DATA_DIR, "benign", filename)):
                    actual_loc = "/data/benign"
                
                print(f"   -> Actual Location:  {actual_loc}")

if __name__ == "__main__":
    check_paths()
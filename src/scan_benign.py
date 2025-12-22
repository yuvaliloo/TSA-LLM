import os
import csv
import hashlib

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# 2. Go up one level to the root (LLM-TSA)
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)

# 3. Point to the data folder
DATA_DIR = os.path.join(PROJECT_ROOT, "data")

# 4. Now define the sub-paths based on that smart DATA_DIR
BENIGN_DIR = os.path.join(DATA_DIR, "benign")
LABELS_FILE = os.path.join(DATA_DIR, "labels.csv")

# 1. Open CSV in append mode
with open(LABELS_FILE, 'a', newline='') as f:
    writer = csv.writer(f)
    
    # 2. Loop through the benign folder
    for filename in os.listdir(BENIGN_DIR):
        filepath = os.path.join(BENIGN_DIR, filename)
        if os.path.isdir(filepath): continue

        # 3. Calculate Hash
        sha256 = hashlib.sha256(open(filepath, 'rb').read()).hexdigest()
        
        # 4. Write: Hash, Filename, "Benign", "Manual"
        writer.writerow([sha256, filename, "Benign", "Manual"])
        print(f"Added {filename}")
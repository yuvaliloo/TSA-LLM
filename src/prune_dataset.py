import os
import csv
import zipfile

# CONFIG
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../data")
LABELS_FILE = os.path.join(DATA_DIR, "labels.csv")
CLEAN_LABELS_FILE = os.path.join(DATA_DIR, "labels_clean.csv")

def is_valid_ooxml(filepath):
    """Returns True if the file is a valid Zip archive (OOXML)"""
    if not os.path.exists(filepath):
        return False
    try:
        with zipfile.ZipFile(filepath, 'r') as z:
            return True
    except zipfile.BadZipFile:
        return False
    except Exception:
        return False

def prune():
    print("--- Pruning Invalid Files (Non-OOXML) ---")
    
    kept = 0
    removed = 0
    
    # Read the current CSV
    if not os.path.exists(LABELS_FILE):
        print("labels.csv not found.")
        return

    with open(LABELS_FILE, 'r') as f_in, open(CLEAN_LABELS_FILE, 'w', newline='') as f_out:
        reader = csv.DictReader(f_in)
        writer = csv.writer(f_out)
        
        # Write Header
        writer.writerow(reader.fieldnames)
        
        for row in reader:
            filename = row['filename']
            label = row['label']
            
            # Find the file
            if label == "Malicious":
                filepath = os.path.join(DATA_DIR, "malware", filename)
            else:
                filepath = os.path.join(DATA_DIR, "benign", filename)
            
            # CHECK VALIDITY
            if is_valid_ooxml(filepath):
                writer.writerow([row['sha256'], row['filename'], row['label'], row['source']])
                kept += 1
            else:
                print(f"[REMOVED] {filename} (Not a valid Zip/OOXML)")
                # Optional: Delete the physical file to save space
                # if os.path.exists(filepath): os.remove(filepath)
                removed += 1

    # Swap the files
    os.replace(CLEAN_LABELS_FILE, LABELS_FILE)
    
    print(f"\n[Done] Kept {kept} valid files. Removed {removed} invalid files.")
    print(f"Now run 'python src/build_dataset.py' again.")

if __name__ == "__main__":
    prune()
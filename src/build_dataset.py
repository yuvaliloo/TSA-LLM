import os
import json
import csv
import hashlib
from Office2JSON import __create_json
from Model import SFEM_Analyzer 

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# 2. Go up one level to the root (LLM-TSA)
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)

# 3. Point to the data folder
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
LABELS_FILE = os.path.join(DATA_DIR, "labels.csv")
OUTPUT_FILE = os.path.join(DATA_DIR, "training_dataset.jsonl")

def calculate_sha256(filepath):
    """Helper to verify we are matching the correct file from CSV"""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def generate_training_entry(filepath, label):
    # --- PHASE 1: FEATURE EXTRACTION (SFEM) ---
    # This is where we convert the binary zip into the "Unique Path List"
    sfem = SFEM_Analyzer(filepath)
    sfem_paths = sfem.extract_structure()
    
    # --- PHASE 2: CONTENT EXTRACTION ---
    # This gets the VBA code and relationships
    content_json = __create_json(filepath)
    # --- PHASE 3: FORMATTING FOR LLM ---
    # We combine both features into the prompt
    user_prompt = f"""
    CONTEXT 1: Structural Paths
    {json.dumps(sfem_paths[:60], indent=2)}

    CONTEXT 2: Extracted Content
    {json.dumps(content_json, indent=2)}
    """
    
    # Create the target output (The "Ground Truth" answer)
    expected_score = 10.0 if label == "Malicious" else 0.0
    expected_output = {
        "score": expected_score,
        "reason": f"Known {label} file hash."
    }

    return {
        "instruction": "Analyze this Office File for malware. Return JSON {score, reason}.",
        "input": user_prompt,
        "output": json.dumps(expected_output)
    }

def main():
    # --- FIX STARTS HERE ---
    
    # 1. Use the dynamic DATA_DIR we calculated at the top
    DIRS = {
        "Malicious": os.path.join(DATA_DIR, "malware"),
        "Benign": os.path.join(DATA_DIR, "benign")
    }
    
    # 2. Use the global variables instead of re-defining hardcoded ones
    # (LABELS_FILE and OUTPUT_FILE are already pointing to the right place)
    
    print(f"--- Building Training Data ---")
    print(f"[*] Reading labels from: {LABELS_FILE}")
    print(f"[*] Outputting to: {OUTPUT_FILE}")

    if not os.path.exists(LABELS_FILE):
        print(f"[!] Error: Labels file not found at {LABELS_FILE}")
        return

    with open(OUTPUT_FILE, 'w') as f_out:
        with open(LABELS_FILE, 'r') as f_in:
            reader = csv.DictReader(f_in)
            
            for row in reader:
                filename=row['filename']
                label = row['label'] 
                # AUTOMATIC PATH FINDING
                folder = DIRS.get(label)
                
                if not folder:
                    print(f"[ERROR] Unknown label '{label}' for {filename}")
                    continue
                    
                filepath = os.path.join(folder, filename)
                
                # Debug print to help you verify paths
                if not os.path.exists(filepath):
                    print(f"[MISSING] {filename} (Looked in: {filepath})")
                    continue

                try:
                    entry = generate_training_entry(filepath, label)
                    f_out.write(json.dumps(entry) + "\n")
                    print(f"[PROCESSED] {filename} -> {label}")
                except Exception as e:
                    print(f"[ERROR] Could not extract features from {filename}: {e}")

if __name__ == "__main__":
    main()
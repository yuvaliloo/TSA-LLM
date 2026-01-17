import sys
import os
import json
import time
from pathlib import Path
# Import the Sentinel class from your main script
from LLMSentinel_v3 import LLMSentinel 

# --- CONFIGURATION ---
TEST_ROOT = Path(r"C:\Users\User\Desktop\LLM-TSA\TSA-LLM\data\test")
MALWARE_DIR = TEST_ROOT / "malware"
BENIGN_DIR = TEST_ROOT / "benign"

def run_full_test():
    print(f"[*] Initializing Sentinel Model...")
    sentinel = LLMSentinel()
    
    # 1. Gather Files
    malware_files = [f for f in MALWARE_DIR.iterdir() if f.is_file()]
    benign_files = [f for f in BENIGN_DIR.iterdir() if f.is_file()]
    
    total_files = len(malware_files) + len(benign_files)
    if total_files == 0:
        print("[!] CRITICAL: No files found in data/test/malware or data/test/benign")
        return

    print(f"[*] Starting Full Evaluation")
    print(f"    - Malware Samples: {len(malware_files)}")
    print(f"    - Benign Samples:  {len(benign_files)}")
    print(f"    - Total to Scan:   {total_files}")
    print("="*60)

    # Metrics
    tp = 0 # True Positive (Malware caught)
    tn = 0 # True Negative (Benign ignored)
    fp = 0 # False Positive (Benign marked as Malware)
    fn = 0 # False Negative (Malware missed)
    errors = 0

    start_time = time.time()

    # --- SCAN MALWARE (Expecting "MALWARE") ---
    print("\n--- PHASE 1: SCANNING MALWARE ---")
    for i, f in enumerate(malware_files, 1):
        print(f"[{i}/{len(malware_files)}] {f.name[:20]:<20} ...", end=" ")
        try:
            result_json = sentinel.analyze(f)
            data = json.loads(result_json)
            verdict = data.get("verdict", "UNKNOWN").upper()
            
            if verdict == "MALWARE":
                print("DETECTED ✅")
                tp += 1
            else:
                print("MISSED ❌")
                fn += 1
        except Exception as e:
            print(f"ERROR: {e}")
            errors += 1

    # --- SCAN BENIGN (Expecting "BENIGN") ---
    print("\n--- PHASE 2: SCANNING BENIGN ---")
    for i, f in enumerate(benign_files, 1):
        print(f"[{i}/{len(benign_files)}] {f.name[:20]:<20} ...", end=" ")
        try:
            result_json = sentinel.analyze(f)
            data = json.loads(result_json)
            verdict = data.get("verdict", "UNKNOWN").upper()
            
            if verdict == "BENIGN":
                print("CLEAN ✅")
                tn += 1
            else:
                print("FALSE ALARM ❌")
                fp += 1
        except Exception as e:
            print(f"ERROR: {e}")
            errors += 1

    # --- FINAL REPORT ---
    end_time = time.time()
    duration = end_time - start_time
    
    # Avoid division by zero
    accuracy = (tp + tn) / total_files if total_files > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    print("\n" + "="*60)
    print("FINAL EVALUATION REPORT")
    print("="*60)
    print(f"Time Taken:    {duration:.2f} seconds ({duration/total_files:.2f}s per file)")
    print(f"Total Scanned: {total_files}")
    print(f"Errors:        {errors}")
    print("-" * 30)
    print(f"True Positives (Caught Virus):  {tp}")
    print(f"False Negatives (Missed Virus): {fn}")
    print(f"True Negatives (Ignored Safe):  {tn}")
    print(f"False Positives (Blamed Safe):  {fp}")
    print("-" * 30)
    print(f"ACCURACY:  {accuracy*100:.2f}%")
    print(f"PRECISION: {precision:.2f}")
    print(f"RECALL:    {recall:.2f}")
    print(f"F1 SCORE:  {f1_score:.2f}")
    print("="*60)

if __name__ == "__main__":
    run_full_test()
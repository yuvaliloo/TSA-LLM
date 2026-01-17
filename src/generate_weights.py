import os
import pandas as pd
from EnsemblePipeline import MalwareEnsemble

# 1. Folders with files we ALREADY know the labels for
# Use about 20-30 files from each for training the weights
TRAIN_FOLDERS = {
    "MALWARE": "../data/train/malware",
    "BENIGN": "../data/train/benign"
}

def create_training_data():
    # Initialize ensemble (it will say 'No weights found', that's fine!)
    engine = MalwareEnsemble()
    training_rows = []

    print("[*] Generating scores for weight training...")

    for label, folder in TRAIN_FOLDERS.items():
        files = os.listdir(folder)[:30] # Use first 30 files from each
        actual_val = 1 if label == "MALWARE" else 0
        
        for f in files:
            path = os.path.join(folder, f)
            try:
                # Get the raw scores before they are averaged
                # We access the internal methods we wrote earlier
                with open(path, "rb") as rb:
                    content = rb.read()
                
                s_score = engine._get_sfem_score(content)
                
                extraction = engine.extractor.extract(path)
                l_score = engine._get_llm_score(extraction)
                
                training_rows.append({
                    "sfem_score": s_score,
                    "llm_score": l_score,
                    "actual": actual_val
                })
                print(f"    [+] Processed {f}: S={s_score:.2f}, L={l_score:.2f}")
            except Exception as e:
                print(f"    [!] Error on {f}: {e}")

    df = pd.DataFrame(training_rows)
    df.to_csv("weight_training_data.csv", index=False)
    print("\n[SUCCESS] 'weight_training_data.csv' created.")

if __name__ == "__main__":
    create_training_data()
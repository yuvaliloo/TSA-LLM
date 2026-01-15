import os
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib
from sfem_features import extract_sfem_features

# CONFIG
DATA_ROOT = "../data/train" # Uses your balanced dataset
MODEL_SAVE_PATH = "../models/sfem_model.pkl"

def load_data_and_extract():
    data_rows = []
    
    # 1. Iterate over Malware and Benign folders
    for label in ["malware", "benign"]:
        folder_path = os.path.join(DATA_ROOT, label)
        y_val = 1 if label == "malware" else 0
        
        print(f"[*] Processing {label}...")
        for filename in os.listdir(folder_path):
            file_path = os.path.join(folder_path, filename)
            
            try:
                with open(file_path, "rb") as f:
                    content = f.read()
                
                # EXTRACT FEATURES
                features = extract_sfem_features(content)
                
                if features:
                    features['label'] = y_val
                    data_rows.append(features)
                    
            except Exception as e:
                pass # Skip broken files

    return pd.DataFrame(data_rows)

def run_training():
    # 1. Create Dataset
    print("[*] Extracting Structural Features from all files...")
    df = load_data_and_extract()
    print(f"[+] Extraction complete. Shape: {df.shape}")

    # 2. Split X and y
    X = df.drop(columns=['label'])
    y = df['label']

    # 3. Train/Test Split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 4. Train Random Forest (The logic engine)
    print("[*] Training SFEM Random Forest...")
    rf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    rf.fit(X_train, y_train)

    # 5. Evaluate
    preds = rf.predict(X_test)
    print("\n--- RESULTS ---")
    print(f"Accuracy: {accuracy_score(y_test, preds):.4f}")
    print(classification_report(y_test, preds))

    # 6. Save
    if not os.path.exists("./models"): os.makedirs("./models")
    joblib.dump(rf, MODEL_SAVE_PATH)
    print(f"[+] Model saved to {MODEL_SAVE_PATH}")

if __name__ == "__main__":
    run_training()
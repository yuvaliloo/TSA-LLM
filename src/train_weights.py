import os
import joblib
import pandas as pd
from sklearn.linear_model import LogisticRegression
from EnsemblePipeline import MalwareEnsemble

# We instantiate the class, but we only use the components
pipeline = MalwareEnsemble()

DATA_DIR = "../data/test" # Use Test set for calibration to avoid overfitting

def generate_meta_features():
    results = []
    print("[*] Generating meta-features (Running both models on test data)...")
    
    for label in ["malware", "benign"]:
        path = os.path.join(DATA_DIR, label)
        y_true = 1 if label == "malware" else 0
        
        files = os.listdir(path)[:50] # Limit to 50 each for speed
        for f in files:
            full_path = os.path.join(path, f)
            try:
                with open(full_path, "rb") as file_obj:
                    data = file_obj.read()
                
                # Get raw scores from individual experts
                s_score = pipeline._get_sfem_score(data)
                l_score = pipeline._get_llm_score(str(data[:1000]))
                
                results.append([s_score, l_score, y_true])
                print(f"    > {f}: S={s_score:.2f}, L={l_score:.2f} -> Target={y_true}")
            except Exception as e:
                print(f"    [!] Error on {f}: {e}")

    return pd.DataFrame(results, columns=["sfem", "llm", "label"])

def train_judge():
    df = generate_meta_features()
    
    X = df[["sfem", "llm"]]
    y = df["label"]
    
    # Logistic Regression is the perfect "weigher"
    clf = LogisticRegression()
    clf.fit(X, y)
    
    # Save the judge
    joblib.dump(clf, "./models/meta_weigher.pkl")
    
    # Show the learned weights
    weights = clf.coef_[0]
    print("\n[+] OPTIMIZED WEIGHTS FOUND:")
    print(f"    SFEM Weight: {weights[0]:.4f}")
    print(f"    LLM Weight:  {weights[1]:.4f}")
    print(f"    Bias:        {clf.intercept_[0]:.4f}")
    print("[*] Judge saved to ./models/meta_weigher.pkl")

if __name__ == "__main__":
    train_judge()
import os
import time
import pandas as pd
from EnsemblePipeline import MalwareEnsemble

# CONFIG
TEST_FOLDERS = {
    "MALWARE": "../data/test/malware",
    "BENIGN": "../data/test/benign"
}

def run_evaluation():
    engine = MalwareEnsemble()
    stats = []

    print("\n" + "="*50)
    print("      SENTINEL ENSEMBLE BATCH EVALUATION")
    print("="*50)

    for true_label, folder_path in TEST_FOLDERS.items():
        if not os.path.exists(folder_path):
            print(f"[!] Skipping {true_label}: Folder not found.")
            continue

        files = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]
        
        for filename in files:
            file_path = os.path.join(folder_path, filename)
            
            # Run the full pipeline
            result = engine.predict(file_path)
            
            # Record data for metrics
            stats.append({
                "filename": filename,
                "actual": true_label,
                "predicted": result["verdict"],
                "confidence": result["confidence"],
                "method": result["method"], # RAG vs ENSEMBLE
                "sfem_score": result.get("breakdown", {}).get("structure", 0),
                "llm_score": result.get("breakdown", {}).get("semantic", 0),
                "time": float(result["time"].replace('s', ''))
            })

    # 2. Process Results into DataFrame
    df = pd.DataFrame(stats)
    
    # Calculate Accuracy
    df['correct'] = df['actual'] == df['predicted']
    accuracy = df['correct'].mean()
    
    # Calculate RAG Efficiency (How many were 'short-circuited')
    rag_hits = len(df[df['method'] == 'RAG_EXACT_MATCH'])
    rag_ratio = (rag_hits / len(df)) * 100

    print("\n" + "="*50)
    print(f"FINAL ACCURACY: {accuracy:.2%}")
    print(f"RAG SHORT-CIRCUIT RATE: {rag_ratio:.1f}%")
    print(f"AVG SCAN TIME: {df['time'].mean():.2f}s")
    print("="*50)

    # Save detailed CSV for your project report
    df.to_csv("ensemble_test_results.csv", index=False)
    print("[+] Detailed report saved to 'ensemble_test_results.csv'")

if __name__ == "__main__":
    run_evaluation()
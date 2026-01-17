import joblib
import pandas as pd
from sklearn.linear_model import LogisticRegression

# 1. Load the "Cheat Sheet" created by your last script
df = pd.read_csv("weight_training_data.csv")

# 2. Define the inputs (Models) and the Goal (Actual Label)
X = df[['sfem_score', 'llm_score']]
y = df['actual']

# 3. Train the "Judge" (The Meta-Classifier)
# We add the "Benign Bias" (0: 2.0) so it's extra careful with False Positives
judge = LogisticRegression(class_weight={0: 2.0, 1: 1.0})
judge.fit(X, y)

# 4. SAVE THE FILE (This stops the "No weights found" error)
joblib.dump(judge, "../models/meta_weigher.pkl")

print("[SUCCESS] Created meta_weigher.pkl in the models folder.")
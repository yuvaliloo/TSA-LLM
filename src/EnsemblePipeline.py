import sys
import os
import joblib
import pandas as pd
import numpy as np
import re
import json
import time
from llama_cpp import Llama 
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename

# Import your custom modules
from sfem_features import extract_sfem_features
from LLMSentinel_v3 import KnowledgeBase, SmartFeatureExtractor
from flasgger import Swagger, swag_from
# --- FLASK SETUP ---
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = '/tmp'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB Limit
Swagger(app)

# --- CONFIG PATHS ---
MODEL_DIR = "./models"
LLM_PATH = os.path.join(MODEL_DIR, "Phi-3-mini-4k-instruct-q4.gguf") 
SFEM_MODEL_PATH = os.path.join(MODEL_DIR, "sfem_model.pkl")
META_MODEL_PATH = os.path.join(MODEL_DIR, "meta_weigher.pkl")
WEIGHTS_CSV_PATH = os.path.join(MODEL_DIR, "weight_training_data.csv")

class MalwareEnsemble:
    def __init__(self):
        print("[*] Initializing Sentinel-Ensemble Pipeline...")
        
        # 1. Load Structural Model (SFEM)
        if os.path.exists(SFEM_MODEL_PATH):
            self.sfem = joblib.load(SFEM_MODEL_PATH)
            print("    [+] SFEM Model loaded.")
        else:
            raise FileNotFoundError(f"SFEM model not found at {SFEM_MODEL_PATH}")

        # 2. Load the Memory Brain (RAG)
        self.memory = KnowledgeBase()
        self.extractor = SmartFeatureExtractor()
        print("    [+] RAG Memory initialized.")

        # 3. Load Semantic Model (LLM)
        print("    [*] Loading LLM (Dedicated RAM)...")
        self.llm = Llama(model_path=LLM_PATH, n_ctx=4096, n_threads=4, verbose=False)
        print("    [+] LLM loaded.")

        # 4. Load Meta-Classifier / CSV Weights
        self.meta_weights = self._load_csv_weights()
        if os.path.exists(META_MODEL_PATH):
            self.meta = joblib.load(META_MODEL_PATH)
            print("    [+] Meta-Classifier model loaded.")
        else:
            self.meta = None
            print("    [!] No Meta-Model found. Falling back to CSV or 50/50.")

    def _load_csv_weights(self):
        """Loads weights from weight.csv if available"""
        if os.path.exists(WEIGHTS_CSV_PATH):
            try:
                df = pd.read_csv(WEIGHTS_CSV_PATH)
                print("    [+] Custom Meta-Weights (CSV) loaded.")
                return df.to_dict('records')[0] # Assumes one row of weights
            except Exception as e:
                print(f"    [!] Error loading CSV weights: {e}")
        return None

    def _get_sfem_score(self, file_bytes):
        feats = extract_sfem_features(file_bytes)
        if feats is None: return 0.5 
        df = pd.DataFrame([feats])
        try:
            return self.sfem.predict_proba(df)[0][1]
        except:
            return 0.5

    def _get_llm_score(self, json_content, rag_context=""):
        prompt = f"""<|user|>
Analyze this document. 
CONTEXT: {rag_context}
[DATA]
{json_content[:3000]}
Return JSON: {{"score": 0.0-1.0, "reason": "..."}}
<|end|>
<|assistant|>
"""
        output = self.llm(prompt, max_tokens=128, stop=["}"], echo=False)
        response = output['choices'][0]['text'] + "}"
        try:
            match = re.search(r"score['\"]?:\s*([0-9.]+)", response)
            if match: return float(match.group(1))
        except: pass
        return 0.5

    def predict(self, file_path):
        start_time = time.time()
        
        # --- PHASE 1: THE FAST TIER ---
        extraction = self.extractor.extract(file_path)
        memories = self.memory.recall(extraction)
        
        rag_verdict = None
        rag_confident = False
        if memories['distances'] and memories['distances'][0][0] < 0.35:
            dist = memories['distances'][0][0]
            rag_verdict = memories['metadatas'][0][0]['label']
            rag_confident = dist < 0.20 

        with open(file_path, "rb") as f:
            content = f.read()
        s_score = self._get_sfem_score(content)
        sfem_verdict = "MALWARE" if s_score >= 0.5 else "BENIGN"
        sfem_confident = s_score > 0.85 or s_score < 0.15

        # --- PHASE 2: ESCALATION LOGIC ---
        if rag_verdict == sfem_verdict:
            return self._format_result(rag_verdict, s_score, "FAST_AGREEMENT", start_time)

        if rag_verdict is not None and rag_confident and sfem_confident:
            return self._run_deep_tier(file_path, extraction, s_score, rag_verdict, start_time)

        if rag_confident and not sfem_confident:
            return self._format_result(rag_verdict, s_score, "RAG_OVERRULE", start_time)
        
        if sfem_confident and not rag_confident:
            return self._format_result(sfem_verdict, s_score, "SFEM_OVERRULE", start_time)

        return self._run_deep_tier(file_path, extraction, s_score, rag_verdict, start_time)

    def _run_deep_tier(self, file_path, extraction, s_score, rag_verdict, start_time):
        rag_hint = f"RAG suggested {rag_verdict}" if rag_verdict else "No RAG match"
        l_score = self._get_llm_score(extraction, rag_context=f"{rag_hint}, SFEM {s_score:.2f}")
        
        # Weighing Strategy
        if self.meta:
            final_prob = self.meta.predict_proba([[s_score, l_score]])[0][1]
        elif self.meta_weights:
            # Use weights from CSV if Meta-Model is missing
            w_sfem = self.meta_weights.get('sfem_weight', 0.5)
            w_llm = self.meta_weights.get('llm_weight', 0.5)
            final_prob = (s_score * w_sfem) + (l_score * w_llm)
        else:
            final_prob = (s_score * 0.4) + (l_score * 0.6)

        return {
            "prediction": "malware" if final_prob >= 0.5 else "benign",
            "confidence": round(float(final_prob), 4),
            "method": "DEEP_LLM_RESOLVED",
            "time": f"{time.time() - start_time:.2f}s"
        }

    def _format_result(self, verdict, s_score, method, start_time):
        # UI expects lowercase 'malware' or 'benign'
        v_clean = verdict.lower()
        conf = s_score if v_clean == "malware" else (1 - s_score)
        return {
            "prediction": v_clean,
            "confidence": round(float(conf), 4),
            "method": method,
            "time": f"{time.time() - start_time:.2f}s"
        }

# --- GLOBAL INITIALIZATION ---
ensemble = MalwareEnsemble()

# --- ROUTES ---
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
@swag_from('scan_docs.yml')
def scan():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            # Run prediction
            result = ensemble.predict(filepath)
            return jsonify(result)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        finally:
            # Clean up uploaded file
            if os.path.exists(filepath):
                os.remove(filepath)

if __name__ == "__main__":
    # In production/Docker, this is handled by Gunicorn, 
    # but this remains for local testing.
    app.run(host="0.0.0.0", port=5000)
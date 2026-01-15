import sys
import os
import joblib
import pandas as pd
import numpy as np
import re  # <--- INJECTED: Required for string extraction
from llama_cpp import Llama 
from sfem_features import extract_sfem_features

# CONFIG
LLM_PATH = "/media/sf_VM_Transfer/llama-3-8b.Q4_K_M.gguf"  # Shared Folder Path
SFEM_MODEL_PATH = "../models/sfem_model.pkl"
META_MODEL_PATH = "../models/meta_weigher.pkl"      # The "Judge" (Weights)

class MalwareEnsemble:
    def __init__(self):
        print("[*] Initializing Ensemble Pipeline...")
        
        # 1. Load Structural Model (SFEM)
        if os.path.exists(SFEM_MODEL_PATH):
            self.sfem = joblib.load(SFEM_MODEL_PATH)
            print("    [+] SFEM Model loaded.")
        else:
            raise FileNotFoundError("Run 'train_sfem.py' first!")

        # 2. Load Semantic Model (LLM)
        # n_gpu_layers=0 for CPU, n_ctx=2048 for context window
        print("    [*] Loading LLM (This takes a moment)...")
        self.llm = Llama(model_path=LLM_PATH, n_ctx=2048, verbose=False)
        print("    [+] LLM loaded.")

        # 3. Load Meta-Classifier (The Weights)
        # If it doesn't exist yet, we use a default 50/50 split
        if os.path.exists(META_MODEL_PATH):
            self.meta = joblib.load(META_MODEL_PATH)
            print("    [+] Learned Weights loaded.")
        else:
            self.meta = None
            print("    [!] No custom weights found. Using default 50/50 split.")

    # --- INJECTED HELPER FUNCTION ---
    def extract_strings(self, data_bytes, min_len=4):
        """
        Simulates the 'strings' command. 
        Extracts readable words (ASCII) from the binary file.
        """
        try:
            # Decode bytes to latin-1 to keep data intact, ignore errors
            text = data_bytes.decode('latin-1', errors='ignore')
            # Regex to find sequences of 4+ readable characters
            tokens = re.findall(r"[A-Za-z0-9_./\\]{4,}", text)
            return " ".join(tokens)
        except Exception:
            return ""
    # -------------------------------

    def _get_sfem_score(self, file_bytes):
        """ Returns probability 0.0 (Safe) to 1.0 (Malware) based on structure """
        feats = extract_sfem_features(file_bytes)
        if feats is None: return 0.5 # Neutral if broken
        
        df = pd.DataFrame([feats])
        try:
            return self.sfem.predict_proba(df)[0][1]
        except:
            return 0.5

    def _get_llm_score(self, text_snippet):
        """ Asks LLM for a risk score 0.0 to 1.0 """
        prompt = f"""
        [SYSTEM] You are a malware analyst. Analyze the following macro code or strings.
        Reply with a JSON object containing a 'score' (0.0 to 1.0) and 'reason'.
        
        [CODE]
        {text_snippet[:1500]} 
        
        [RESPONSE]
        """
        output = self.llm(prompt, max_tokens=64, stop=["}"], echo=False)
        response = output['choices'][0]['text']
        
        # Look for the number after "score":
        match = re.search(r"score['\"]?:\s*([0-9.]+)", response)
        if match:
            return float(match.group(1))
        return 0.5 # Fallback

    def predict(self, file_path):
        print(f"[*] Analyzing: {os.path.basename(file_path)}")
        
        # Read File
        with open(file_path, "rb") as f:
            content = f.read()
        
        # 1. Structural Analysis
        s_score = self._get_sfem_score(content)
        
        # 2. Semantic Analysis (FIXED: Uses String Extraction)
        # We scan the first 10,000 bytes to dig past the Zip header
        clean_text = self.extract_strings(content[:10000])
        
        # Pass the extracted strings (up to 2000 chars) to the LLM
        l_score = self._get_llm_score(clean_text[:2000])
        
        # 3. Weighted Vote
        if self.meta:
            final_prob = self.meta.predict_proba([[s_score, l_score]])[0][1]
        else:
            final_prob = (s_score * 0.5) + (l_score * 0.5)

        return {
            "verdict": "MALWARE" if final_prob > 0.5 else "BENIGN",
            "confidence": final_prob,
            "breakdown": {"structure": s_score, "semantic": l_score}
        }
import sys
import os
import json
import zipfile
import re
import glob
import time
import shutil
import tempfile
import chromadb
import gc
from pathlib import Path
from llama_cpp import Llama
from oletools.olevba import VBA_Parser
from sentence_transformers import SentenceTransformer

# --- CONFIGURATION ---
MODEL_PATH = "../models/Phi-3-mini-4k-instruct-q4.gguf" 
EMBEDDING_PATH = "../models/all-MiniLM-L6-v2"
CONTEXT_SIZE = 4096 
MAX_INPUT_CHARS = 6000 
# CRITICAL: If a file is closer than this distance, we trust the DB blindly.
# Lower = Stricter (Must be more identical). 0.35 is a good "Similar Logic" threshold.
RAG_THRESHOLD = 0.35 

class SmartFeatureExtractor:
    def smart_cut(self, text, limit):
        if not text: return ""
        if len(text) <= limit: return text
        half = int(limit / 2)
        return text[:half] + f"\n...[SNIPPED]...\n" + text[-half:]

    def _read_file_content(self, full_path, filename):
        lower_name = filename.lower()
        if lower_name.endswith((".xml", ".rels")):
            try:
                with open(full_path, 'r', encoding="utf8", errors="ignore") as f:
                    return f.read().replace('"', "'") 
            except: return ""
        elif lower_name.endswith("vbaproject.bin"):
            try:
                vbaparser = VBA_Parser(full_path)
                data = { "macros": [], "analysis": [] }
                if vbaparser.detect_vba_macros():
                    for (_, _, vba_filename, vba_code) in vbaparser.extract_macros():
                        if vba_code:
                            clean_code = "\n".join([l.strip() for l in vba_code.splitlines() if l.strip()])
                            data["macros"].append({ "filename": vba_filename, "code": self.smart_cut(clean_code, 1000) })
                    for (type_, keyword, desc) in vbaparser.analyze_macros():
                        data["analysis"].append({ "type": type_, "keyword": keyword, "description": desc })
                vbaparser.close()
                return data if data["macros"] else "No Macros Detected"
            except: return "Error parsing VBA"
        elif any(lower_name.endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".gif"]): return ""
        elif lower_name.endswith(".vml"): return "*vector markup language file*"
        else: return "*file type unknown, raise suspicion!*"

    def _build_hierarchy(self, folder_path):
        data = {}
        for root, _, f_names in os.walk(folder_path):
            rel_path = os.path.relpath(root, folder_path)
            if rel_path == ".": path_parts = []
            else: path_parts = rel_path.split(os.sep)
            curr_dict = data
            for part in path_parts:
                if part not in curr_dict: curr_dict[part] = {}
                curr_dict = curr_dict[part]
                if not isinstance(curr_dict, dict): curr_dict = {}
            for f in f_names:
                curr_dict[f] = self._read_file_content(os.path.join(root, f), f)
        return data

    def extract(self, file_path):
        file_path = Path(file_path).resolve()
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_zip_path = os.path.join(temp_dir, "target.zip")
            extract_folder = os.path.join(temp_dir, "extracted")
            try:
                shutil.copy(file_path, temp_zip_path)
                with zipfile.ZipFile(temp_zip_path, "r") as zf:
                    zf.extractall(extract_folder)
                full_json_struct = self._build_hierarchy(extract_folder)
                json_str = json.dumps(full_json_struct, indent=2)
                return self.smart_cut(json_str, MAX_INPUT_CHARS)
            except zipfile.BadZipfile:
                return json.dumps({"error": "Not a valid ZIP/Office file", "type": "Binary/Legacy"})
            except Exception as e:
                return json.dumps({"error": str(e)})

class KnowledgeBase:
    def __init__(self, db_path="./sentinel_memory"):
        self.client = chromadb.PersistentClient(path=db_path)
        if os.path.exists(EMBEDDING_PATH):
            self.embedder = SentenceTransformer(EMBEDDING_PATH)
        else:
            self.embedder = SentenceTransformer('all-MiniLM-L6-v2')
        self.collection = self.client.get_or_create_collection("malware_patterns")

    def learn(self, file_path, label, extraction_text):
        if len(extraction_text) < 50: return
        file_id = f"{label}_{os.path.basename(file_path)}"
        embedding = self.embedder.encode(extraction_text).tolist()
        try:
            self.collection.add(
                documents=[extraction_text],
                metadatas=[{"label": label, "filename": os.path.basename(file_path)}],
                ids=[file_id],
                embeddings=[embedding]
            )
            print(f"[+] Learned: {os.path.basename(file_path)}")
        except: pass

    def recall(self, extraction_text, n_results=1):
        embedding = self.embedder.encode(extraction_text).tolist()
        results = self.collection.query(
            query_embeddings=[embedding],
            n_results=n_results
        )
        return results

class LLMSentinel:
    def __init__(self):
        if not os.path.exists(MODEL_PATH):
            print(f"[!] WARNING: Model not found at {MODEL_PATH}")
        
        # Load Model ONCE
        self.llm = Llama(model_path=MODEL_PATH, n_ctx=CONTEXT_SIZE, n_threads=4, verbose=False)
        self.extractor = SmartFeatureExtractor()
        self.memory = KnowledgeBase()

    def train_mode(self, folder_path, label):
        if not os.path.isdir(folder_path): return
        files = glob.glob(os.path.join(folder_path, "*"))
        files = [f for f in files if os.path.isfile(f) and not f.endswith(".py")]
        print(f"[*] Training on {len(files)} files...")
        for f in files:
            try:
                content = self.extractor.extract(f)
                self.memory.learn(f, label, content)
            except: pass

    def analyze(self, file_path):
        import gc
        gc.collect() 
        try:
            llm_input = self.extractor.extract(file_path)
            
            # --- RAG STEP ---
            memories = self.memory.recall(llm_input)
            rag_context = ""
            
            if memories['documents'] and memories['documents'][0]:
                match_label = memories['metadatas'][0][0]['label']
                match_name = memories['metadatas'][0][0]['filename']
                distance = memories['distances'][0][0] 

                # 1. EXACT MALWARE MATCH (Strict)
                if match_label == "MALWARE" and distance < 0.35:
                    return json.dumps({
                        "verdict": "MALWARE",
                        "malscore": 10.0,
                        "reasoning": f"Exact malware match found ({match_name}) | Dist: {distance:.4f}",
                        "time": "0.05s (DB)"
                    })

                # 2. BENIGN PRIORITY (Relaxed)
                # We give benign matches more 'grace' (0.45 vs 0.35) to reduce false positives
                if match_label == "BENIGN" and distance < 0.45:
                    return json.dumps({
                        "verdict": "BENIGN",
                        "malscore": 0.0,
                        "reasoning": f"Strong similarity to known safe file ({match_name}) | Dist: {distance:.4f}",
                        "time": "0.05s (DB)"
                    })

                rag_context = f"[SIMILAR CASE]\nFilename: {match_name}\nVerdict: {match_label}\nDist: {distance:.4f}"

            # --- LLM STEP (The 'Thinking' Path) ---
            # We raise the AI's internal threshold to 5.0 to be more conservative
            prompt = f"""<|user|>
Assess this Office document.
CONTEXT: {rag_context}
INSTRUCTIONS:
1. If the [SIMILAR CASE] is BENIGN with a low distance, favor a BENIGN verdict.
2. If suspicious macros or obfuscated PowerShell are found, flag as MALWARE.
3. Return XML with score 0.0-10.0.
[INPUT] <json_content>{llm_input}</json_content><|end|>
<|assistant|>
<assessment><summary>"""

            start_t = time.time()
            output = self.llm(prompt, max_tokens=128, stop=["</assessment>"], temperature=0.1, echo=False)
            inference_time = time.time() - start_t
            
            raw_output = output['choices'][0]['text'].strip()
            full_output = "<assessment><summary>" + raw_output + "</assessment>"
            
            verdict = "BENIGN"; score = 0.0; reasoning = "Analysis failed"
            try:
                summary_match = re.search(r"<summary>(.*?)</summary>", full_output, re.DOTALL)
                if summary_match: reasoning = summary_match.group(1).strip()
                score_match = re.search(r"<score>(.*?)</score>", full_output, re.DOTALL)
                if score_match: score = float(score_match.group(1).strip())
                
                # Decision Boundary: Adjusted to 5.0 to reduce false alarms (Paper used 3.0)
                if score >= 5.0: 
                    verdict = "MALWARE"
            except:
                if "MALWARE" in raw_output.upper(): score = 8.0; verdict = "MALWARE"

            return json.dumps({ "verdict": verdict, "malscore": score, "reasoning": reasoning, "time": f"{inference_time:.2f}s" })

        except Exception as e:
            return json.dumps({ "verdict": "ERROR", "details": str(e) })

if __name__ == "__main__":
    sentinel = LLMSentinel()
    
    if len(sys.argv) > 2 and sys.argv[1] == "--train":
        sentinel.train_mode(sys.argv[2], sys.argv[3])
    elif len(sys.argv) > 1:
        target = sys.argv[1]
        if os.path.isdir(target):
            files = glob.glob(os.path.join(target, "*"))
            files = [f for f in files if os.path.isfile(f) and not f.endswith(".py")]
            print(f"[*] Batch Scanning {len(files)} files...")
            for f in files:
                # Print simplified output for cleaner logs
                res = json.loads(sentinel.analyze(f))
                print(f"{os.path.basename(f)} : {res['verdict']} ({res['malscore']}) [{res['time']}]")
        else:
            print(sentinel.analyze(target))
    else:
        print("Usage:\n Train: python LLMSentinel.py --train ./data/malware MALWARE\n Scan:  python LLMSentinel.py ./path/to/scan")
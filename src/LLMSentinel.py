import sys
import os
import zipfile
import json
import re
import io
from llama_cpp import Llama

# --- CONFIGURATION ---
# Path to your GGUF model in the Shared Folder
MODEL_PATH = "/media/sf_VM_Transfer/llama-3-8b.Q4_K_M.gguf"
CONTEXT_SIZE = 2048  # Kept at 2048 to save RAM

class OfficeJSONConverter:
    """
    Simulates the 'office2JSON' tool.
    Converts binary .docm/.xlsx files into a text-based JSON report.
    """
    def convert(self, file_bytes):
        report = {
            "metadata": {"is_valid_zip": False, "extensions": []},
            "content": {"body_text": "", "external_links": []},
            "macros": {"has_vba": False, "suspicious_strings": []},
            "structure": {"files_inside": []}
        }

        try:
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
                report["metadata"]["is_valid_zip"] = True
                all_files = zf.namelist()
                report["structure"]["files_inside"] = all_files
                report["metadata"]["extensions"] = list(set([f.split('.')[-1] for f in all_files if '.' in f]))

                # 1. Extract Body Text (word/document.xml or xl/sharedStrings.xml)
                text_content = ""
                if "word/document.xml" in all_files:
                    text_content = zf.read("word/document.xml").decode(errors='ignore')
                elif "xl/sharedStrings.xml" in all_files:
                    text_content = zf.read("xl/sharedStrings.xml").decode(errors='ignore')
                
                # Strip XML tags to get raw text
                clean_text = re.sub(r'<[^>]+>', ' ', text_content)
                report["content"]["body_text"] = " ".join(clean_text.split())[:500] # Limit to 500 chars

                # 2. Extract External Links (Phishing detection)
                # Links usually live in .rels files
                for f in all_files:
                    if f.endswith(".rels"):
                        rels_data = zf.read(f).decode(errors='ignore')
                        links = re.findall(r'Target="http[^"]+"', rels_data)
                        report["content"]["external_links"].extend([l.replace('Target="', '').replace('"', '') for l in links])

                # 3. Extract Macros (vbaProject.bin)
                # We use 'strings' extraction on the binary blob
                bin_files = [f for f in all_files if f.endswith(".bin")]
                if bin_files:
                    report["macros"]["has_vba"] = True
                    for b_file in bin_files:
                        bin_data = zf.read(b_file)
                        # Extract readable ASCII strings > 5 chars
                        strings = re.findall(r"[A-Za-z0-9_./\\]{5,}", bin_data.decode('latin-1', errors='ignore'))
                        
                        # FILTER: Only keep suspicious keywords to save Context Window
                        keywords = ["AutoOpen", "Document_Open", "Shell", "CreateObject", 
                                    "powershell", "cmd.exe", "http", "download", "temp", "URLDownloadToFile"]
                        
                        suspicious = [s for s in strings if any(k.lower() in s.lower() for k in keywords)]
                        report["macros"]["suspicious_strings"].extend(list(set(suspicious)))

        except zipfile.BadZipFile:
            report["error"] = "File is not a valid zip archive (possible exploit or binary format)"
        except Exception as e:
            report["error"] = str(e)

        return json.dumps(report, indent=2)


class LLMSentinel:
    def __init__(self):
        print(f"[*] Loading LLM-Sentinel ({MODEL_PATH})...")
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(f"Model not found at {MODEL_PATH}")
            
        self.llm = Llama(
            model_path=MODEL_PATH,
            n_ctx=CONTEXT_SIZE,
            n_gpu_layers=0,  # CPU only
            verbose=False
        )
        self.converter = OfficeJSONConverter()
        print("[+] Model Loaded.")

    def analyze(self, file_path):
        print(f"[*] Processing: {os.path.basename(file_path)}")
        
        # 1. Read File
        with open(file_path, "rb") as f:
            content = f.read()

        # 2. Convert to JSON
        # We get the raw JSON string from the converter
        full_json_str = self.converter.convert(content)
        
        # SAFEGUARD: Slice it to ensure it fits in the 2048 context window.
        # We take the first 1500 chars which includes metadata and macros.
        llm_input = full_json_str[:1500]

        # 3. Construct Prompt (THE FIX: Pre-fill the response)
        # We force the LLM to start with "analysis" so it cannot output an empty "}"
        prompt = f"""
[SYSTEM]
You are a cybersecurity expert analyzing a JSON report of an Office file.
Your task is to determine if the file contains malicious macros (Shell, PowerShell, AutoOpen).

[DATA]
{llm_input}

[INSTRUCTIONS]
Reply with a JSON object. You must explain your reasoning first.

[YOUR RESPONSE]
{{
  "analysis": "
""" 
        # Note: We deliberately leave the JSON open above ^

        # 4. Run Inference
        output = self.llm(
            prompt, 
            max_tokens=256, 
            stop=["}"], # Stop when it tries to close the JSON object
            echo=False
        )
        
        # 5. Reconstruct the JSON
        # We manually stitch the pre-filled part back to the generated part
        generated_text = output['choices'][0]['text']
        full_response = '{ "analysis": "' + generated_text
        
        # Ensure it ends with a brace (in case max_tokens cut it off)
        if not full_response.strip().endswith("}"): 
            full_response += "}"
            
        return full_response

# --- RUN BLOCK ---
if __name__ == "__main__":
    sentinel = LLMSentinel()
    
    # Test on a random file from your test set
    target_dir = "../data/test/malware"
    
    # Simple check to allow running without crashing if folder is missing
    if os.path.exists(target_dir) and len(os.listdir(target_dir)) > 0:
        import random
        filename = random.choice(os.listdir(target_dir))
        full_path = os.path.join(target_dir, filename)
        
        result = sentinel.analyze(full_path)
        print("\n--- LLM REPORT ---")
        print(result)
    else:
        print(f"Please point the script to a valid file path manually. (Checked: {target_dir})")
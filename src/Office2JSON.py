import os
import shutil
import zipfile
import subprocess
import json
import time
import sys
from llama_cpp import Llama

# --- CONFIGURATION ---
LLM_PATH = "/media/sf_VM_Transfer/llama-3-8b.gguf"
CONTEXT_SIZE = 4096

class OfficeToJSON:
    """
    Your custom extractor logic, refactored to return data to memory
    instead of writing files to disk.
    """
    def __create_json(self, folder_path):
        data = {}
        for root, d_names, f_names in os.walk(folder_path):
            rel = os.path.relpath(root, folder_path)
            parts = rel.split(os.sep)
            curr = data
            for part in parts:
                if part == ".": continue
                curr = curr.setdefault(part, {})
            for f in f_names:
                curr[f] = self.read_file_content(root, f)
        return data

    def read_file_content(self, path, file_name):
        file_path = os.path.join(path, file_name)

        # 1. Read XML / Rels (Structure)
        if file_path.endswith((".xml", ".rels")):
            try:
                with open(file_path, encoding="utf-8", errors="ignore") as f:
                    # Truncate huge XML files to avoid crashing the LLM
                    return f.read().replace('"', "'")[:1000] 
            except:
                return ""

        # 2. Decompile Macros using OLEVBA (The "Magic" Step)
        elif file_path.endswith("vbaProject.bin"):
            try:
                # We assume 'olevba' is installed in the system path
                output = subprocess.check_output(
                    ["olevba", "--json", file_path],
                    stderr=subprocess.DEVNULL
                ).decode("utf-8")

                # Parse olevba's JSON output
                start = output.find("{")
                end = output.rfind("}") + 1
                if start != -1 and end != -1:
                    return json.loads(output[start:end])
                return {"error": "olevba parse failed"}
            except Exception as e:
                return {"error": "olevba not found or failed", "details": str(e)}

        elif file_path.lower().endswith((".png", ".jpg", ".jpeg")):
            return "<image_file_skipped>"
        elif file_path.endswith(".vml"):
            return "<vector_markup_language>"
        else:
            return "<unknown_file_type>"

    def extract_to_memory(self, file_path):
        """
        Extracts, converts, and cleans up temp files immediately.
        Returns: Dict (The JSON object)
        """
        abs_path = os.path.abspath(file_path)
        base_dir = os.path.dirname(abs_path)
        file_name = os.path.basename(abs_path)

        # Create unique temp dir to avoid collisions
        temp_id = str(int(time.time()))
        temp_zip = os.path.join(base_dir, f"temp_{temp_id}.zip")
        temp_dir = os.path.join(base_dir, f"temp_ext_{temp_id}")

        try:
            shutil.copy(abs_path, temp_zip)
            with zipfile.ZipFile(temp_zip, "r") as z:
                z.extractall(temp_dir)
            
            # Use your logic to build the dict
            json_dict = self.__create_json(temp_dir)
            return json_dict

        except Exception as e:
            return {"error": str(e)}
        finally:
            # CLEANUP: Delete the temp files immediately
            if os.path.exists(temp_zip): os.remove(temp_zip)
            if os.path.exists(temp_dir): shutil.rmtree(temp_dir)


class LLMSentinel:
    def __init__(self):
        print(f"[*] Loading LLM-Sentinel (Advanced)...")
        if not os.path.exists(LLM_PATH):
            raise FileNotFoundError(f"Model not found at {LLM_PATH}")
            
        self.llm = Llama(
            model_path=LLM_PATH,
            n_ctx=CONTEXT_SIZE,
            verbose=False
        )
        self.extractor = OfficeToJSON()
        print("[+] System Ready.")

    def analyze(self, file_path):
        print(f"[*] Extracting JSON representation: {os.path.basename(file_path)}")
        
        # 1. Run your extractor
        full_data = self.extractor.extract_to_memory(file_path)
        
        # 2. Convert to string and TRUNCATE for LLM
        # Llama-3 cannot read a 10MB JSON file. We must prioritize the Macros.
        json_str = json.dumps(full_data, indent=2)
        
        # Smart Truncation: Keep the first 3500 chars (likely metadata + start of macros)
        # If you have specific keys you want to prioritize, you'd filter the dict first.
        llm_input = json_str[:3500]

        # 3. The Prompt
        prompt = f"""
[SYSTEM]
You are a malware analyst. Review this JSON dump of an Office file structure.
Focus on 'vbaProject.bin' and 'macros'.
If you see suspicious code (Shell, AutoOpen, powershell), mark as MALWARE.

[FILE DATA]
{llm_input}

[INSTRUCTIONS]
Reply with valid JSON only:
{{
  "verdict": "MALWARE" or "BENIGN",
  "confidence": 0.0 to 1.0,
  "reason": "short explanation"
}}
"""
        print(f"[*] Sending to Llama-3...")
        output = self.llm(
            prompt, 
            max_tokens=128, 
            stop=["}"], 
            echo=False
        )
        
        response = output['choices'][0]['text'].strip()
        if not response.endswith("}"): response += "}"
        return response

if __name__ == "__main__":
    sentinel = LLMSentinel()
    
    # Test on a file
    # Make sure to point this to a real file in your test set!
    test_file = "../data/test/malware/1ac8c6e43264d5f82d7e80229c75e5d2a9130fb10a23d20cac4fc0412db14b22.doc"
    
    if os.path.exists(test_file):
        result = sentinel.analyze(test_file)
        print("\n--- FINAL VERDICT ---")
        print(result)
    else:
        print(f"Please update the 'test_file' path in the script. Could not find: {test_file}")
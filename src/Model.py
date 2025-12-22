import zipfile
import json
import os
from lxml import etree
import ollama  # <--- NEW: Requires 'pip install ollama'

# --- IMPORT YOUR MODULE ---
from Office2JSON import __create_json

class SFEM_Analyzer:
    """ (Kept EXACTLY the same as before) """
    NAMESPACES = {
        'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main',
        'r': 'http://schemas.openxmlformats.org/officeDocument/2006/relationships',
        'p': 'http://schemas.openxmlformats.org/presentationml/2006/main',
        'a': 'http://schemas.openxmlformats.org/drawingml/2006/main',
    }

    def __init__(self, filepath):
        self.filepath = filepath
        self.unique_paths = set()

    def _clean_tag(self, tag):
        if '}' in tag:
            ns_url, tag_name = tag[1:].split('}')
            for prefix, url in self.NAMESPACES.items():
                if ns_url == url:
                    return f"{prefix}:{tag_name}"
            return tag_name
        return tag

    def _recurse_xml(self, element, current_path):
        tag_name = self._clean_tag(element.tag)
        new_path = f"{current_path}\\{tag_name}" if current_path else tag_name
        self.unique_paths.add(new_path)
        for child in element:
            self._recurse_xml(child, new_path)

    def extract_structure(self):
        if not zipfile.is_zipfile(self.filepath):
            return []
        try:
            with zipfile.ZipFile(self.filepath, 'r') as z:
                file_list = z.namelist()
                for f in file_list:
                    path_str = f.replace('/', '\\')
                    self.unique_paths.add(path_str)
                    if f.endswith('.xml') or f.endswith('.rels'):
                        try:
                            xml_content = z.read(f)
                            root = etree.fromstring(xml_content)
                            self._recurse_xml(root, path_str)
                        except etree.XMLSyntaxError:
                            pass
        except Exception as e:
            print(f"SFEM Error: {e}")
        return sorted(list(self.unique_paths))

    def run_sieve(self):
        self.extract_structure()
        suspicious_triggers = [
            "vbaProject.bin", "macrosheets", "activeX", "oleObject", "w:fldSimple"
        ]
        for path in self.unique_paths:
            for trigger in suspicious_triggers:
                if trigger in path:
                    return True
        return False

class LocalMalwareScanner:
    """Stage 3: The Brain (Powered by Local Ollama)"""
    
    def __init__(self, model_name="malware-scanner"):
        self.model = model_name

    def analyze(self, content_json, sfem_paths):
        # 1. Prepare Data
        # We slice sfem_paths[:60] to prevent overflowing the context window
        sfem_str = json.dumps(list(sfem_paths)[:60], indent=2)
        content_str = json.dumps(content_json, indent=2)
        
        # 2. Construct the Prompt
        # This matches the structure we used in training (Instruction + Context)
        user_message = f"""
        Analyze this Office File for malware. Return JSON {{score, reason}}.

        CONTEXT 1: Structural Paths
        {sfem_str}

        CONTEXT 2: Extracted Content
        {content_str}
        """

        try:
            # 3. Call Local Ollama Model
            response = ollama.chat(
                model=self.model,
                messages=[{
                    'role': 'user',
                    'content': user_message
                }],
                # Optional: Force JSON mode if your version supports it, 
                # but our Modelfile system prompt already handles this.
                format='json' 
            )
            return response['message']['content']
            
        except Exception as e:
            return json.dumps({
                "score": -1.0, 
                "reason": f"Ollama Connection Error: {str(e)}"
            })

def main():
    # Use dynamic path so it works on both Docker and Local
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
    DATA_DIR = os.path.join(PROJECT_ROOT, "data", "malware") 
    # ^ Changed to 'malware' folder for testing, or use 'benign'

    analyst = LocalMalwareScanner()
    
    print(f"--- Local Malware Scanner (Ollama) ---")
    print(f"[*] Scanning folder: {DATA_DIR}")

    if not os.path.exists(DATA_DIR):
        print("[-] Data directory not found.")
        return

    for filename in os.listdir(DATA_DIR):
        filepath = os.path.join(DATA_DIR, filename)
        
        # Skip directories
        if os.path.isdir(filepath): continue

        print(f"\n[?] Checking: {filename}")
        
        # 1. SFEM Analysis (The Sieve)
        sfem_tool = SFEM_Analyzer(filepath)
        if not sfem_tool.run_sieve():
            print(f"    -> [CLEAN] Structure looks benign. Skipping AI.")
            continue
            
        print(f"    -> [SUSPICIOUS] Sieve triggered! Sending to AI...")
        
        # 2. Extract Content
        # (Assuming Office2JSON works; wrapping in try/except just in case)
        try:
            extractor = __create_json(filepath) 
            evidence_json = extractor.run()
        except Exception as e:
            print(f"    -> [ERROR] Extraction failed: {e}")
            continue

        # 3. Analyze with Ollama
        verdict_str = analyst.analyze(evidence_json, sfem_tool.unique_paths)
        print(f"    -> AI VERDICT: {verdict_str}")

if __name__ == "__main__":
    main()
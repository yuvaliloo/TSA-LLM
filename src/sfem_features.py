import zipfile
import io
import numpy as np
import os

# Key structural indicators from ALDOCX research
IMPORTANT_PATHS = [
    "word/vbaProject.bin", "xl/vbaProject.bin", "ppt/vbaProject.bin",
    "word/vbaData.xml", "customXml/item1.xml", "word/embeddings/oleObject",
    "word/activeX", "[Content_Types].xml"
]

def extract_sfem_features(file_bytes):
    features = {}
    try:
        # Open file in memory as a Zip
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
            all_paths = zf.namelist()
            
            # 1. Counts
            features['num_files'] = len(all_paths)
            features['num_xml'] = len([p for p in all_paths if p.endswith('.xml')])
            features['num_bin'] = len([p for p in all_paths if p.endswith('.bin')])
            features['num_png'] = len([p for p in all_paths if p.lower().endswith('.png')])

            # 2. Suspicious Path Check
            for key in IMPORTANT_PATHS:
                clean_key = key.replace("/", "_").replace("[", "").replace("]", "")
                features[f'has_{clean_key}'] = 1 if any(key in p for p in all_paths) else 0

            # 3. Anomalies (e.g. extremely long paths are suspicious)
            lengths = [len(p) for p in all_paths]
            features['avg_path_len'] = np.mean(lengths) if lengths else 0

    except Exception:
        return None # Return None if file is not a valid Office/Zip file

    return features
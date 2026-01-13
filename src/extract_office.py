import os
import zipfile
import pyzipper
from io import BytesIO

# CONFIG
SOURCE_ZIP = "../data/2026-01-02.zip"  # <--- Update this to your local file
TARGET_DIR = "../data/malware"
PASSWORD = b"infected"

def get_office_type(content):
    """
    Only called if we already know it's a Zip file.
    Checks internal structure for word/xl/ppt.
    """
    try:
        with zipfile.ZipFile(BytesIO(content)) as zf:
            names = zf.namelist()
            
            # Check for macros (vbaProject.bin)
            has_macros = any('vbaProject.bin' in n for n in names)
            
            if any(n.startswith('word/') for n in names):
                return ".docm" if has_macros else ".docx"
            if any(n.startswith('xl/') for n in names):
                return ".xlsm" if has_macros else ".xlsx"
            if any(n.startswith('ppt/') for n in names):
                return ".pptm" if has_macros else ".pptx"
    except:
        return None
    return None

def run():
    if not os.path.exists(SOURCE_ZIP):
        print(f"[-] Error: {SOURCE_ZIP} not found.")
        return

    if not os.path.exists(TARGET_DIR):
        os.makedirs(TARGET_DIR)

    print(f"[*] Speed-Scanning: {SOURCE_ZIP}")
    
    extracted = 0
    skipped = 0
    
    try:
        with pyzipper.AESZipFile(SOURCE_ZIP) as zf:
            zf.setpassword(PASSWORD)
            file_list = zf.namelist()
            total = len(file_list)
            print(f"[*] Archive contains {total} files.")

            for i, member in enumerate(file_list):
                # PROGRESS INDICATOR (Every 500 files)
                if i % 500 == 0:
                    print(f"    > Progress: {i}/{total} checked...")

                with zf.open(member) as f:
                    # OPTIMIZATION: Read ONLY the first 4 bytes!
                    header = f.read(4)
                    
                    # If it's not a Zip (PK..), it CANNOT be an Office file.
                    # Skip it immediately.
                    if header != b'PK\x03\x04':
                        skipped += 1
                        continue
                    
                    # If we are here, it MIGHT be a doc. Read the rest.
                    content = header + f.read()
                    
                    ext = get_office_type(content)
                    if ext:
                        safe_name = os.path.basename(member) + ext
                        out_path = os.path.join(TARGET_DIR, safe_name)
                        
                        if not os.path.exists(out_path):
                            with open(out_path, "wb") as f_out:
                                f_out.write(content)
                            extracted += 1
                            print(f"      [+] Found {ext} file! (Total: {extracted})")

    except Exception as e:
        print(f"[-] Error: {e}")

    print("-" * 30)
    print(f"[+] DONE.")
    print(f"    Scanned: {total}")
    print(f"    Skipped (Junk): {skipped}")
    print(f"    Extracted (Docs): {extracted}")

if __name__ == "__main__":
    run()
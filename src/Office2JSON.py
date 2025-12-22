import shutil
import zipfile
import os
import argparse
import subprocess
import json
import time


def __create_json(folder_path):
    data = {}

    for root, d_names, f_names in os.walk(folder_path):
        rel = os.path.relpath(root, folder_path)
        parts = rel.split(os.sep)

        curr = data
        for part in parts:
            if part == ".":
                continue
            curr = curr.setdefault(part, {})

        for f in f_names:
            curr[f] = read_file_content(root, f)

    return data


def read_file_content(path, file_name):
    file_path = os.path.join(path, file_name)

    if file_path.endswith((".xml", ".rels")):
        with open(file_path, encoding="utf-8", errors="ignore") as f:
            return f.read().replace('"', "'")

    elif file_path.endswith("vbaProject.bin"):
        try:
            output = subprocess.check_output(
                ["olevba", "--json", file_path],
                stderr=subprocess.DEVNULL
            ).decode("utf-8")

            start = output.find("{")
            end = output.rfind("}") + 1
            return json.loads(output[start:end])

        except Exception:
            return ""

    elif file_path.lower().endswith((".png", ".jpg", ".jpeg")):
        return ""

    elif file_path.endswith(".vml"):
        return "*vector markup language file*"

    else:
        return "*file type unknown, raise suspicion!*"


def extract(file_path):
    abs_path = os.path.abspath(file_path)
    base_dir = os.path.dirname(abs_path)
    file_name = os.path.basename(abs_path)

    temp_zip = os.path.join(base_dir, os.path.splitext(file_name)[0] + ".zip")
    temp_dir = os.path.join(base_dir, "temp_extraction")

    shutil.copy(abs_path, temp_zip)

    with zipfile.ZipFile(temp_zip, "r") as z:
        z.extractall(temp_dir)

    os.remove(temp_zip)

    json_dict = __create_json(temp_dir)

    out_file = os.path.join(base_dir, f"extracted_{file_name}.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(json_dict, f, indent=4)

    shutil.rmtree(temp_dir)


if __name__ == "__main__":
    start = time.time()

    parser = argparse.ArgumentParser("Office2JSON")
    parser.add_argument("file", help="Path to .docx/.xlsx file")
    args = parser.parse_args()

    extract(args.file)

    print("_" * 40)
    print(f"Extraction time:\t{round(time.time() - start, 3)}s")
    print(f"Output file:\t\textracted_{os.path.basename(args.file)}.json")
    print("_" * 40)

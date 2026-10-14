import os
import shutil
import subprocess
import sys
import pandas as pd
import requests
from io import StringIO
import argparse
import json

REPO_URL = "https://github.com/Samsung/CredData.git"
# CredData is still being updated, so the versions are pinned:
#  - DATA_COMMIT: snapshot used to download the repositories (December 2025, 331 repositories)
#  - META_COMMIT: labels (meta/*.csv) used for the evaluation in the paper (September 2026)
# The data set of the paper was downloaded in late 2025; a new download with DATA_COMMIT gives
# the same 331 repositories and the same split, but a few files differ, so the counts can differ slightly.
DATA_COMMIT = "e7348eafce1e3ded950482e24fd27d026356ed81"
META_COMMIT = "c09c0c52fc6dae4ae5438ae69ba486f9f8059f0d"
BENCHMARK_DIR = "benchmark"
REPO_DIR = os.path.join(BENCHMARK_DIR, "CredData")
UPGRADE_DIR = os.path.join("upgrade","benchmark","CredData")
DATA_DIR = os.path.join(REPO_DIR, "data")


def run(cmd, cwd=None):
    subprocess.check_call(cmd, cwd=cwd, shell=True)

def get_groundtruth_lines(filename):
    """
    Read ground truth data from Samsung CredData repository
    
    Args:
        filename: File name without extension (e.g., 'bucket_s3')
    
    Returns:
        dict: Dictionary where keys are FileID and values are lists of LineStart 
              numbers where GroundTruth is 'T'
              Example: {'file1.py': [10, 25, 42], 'file2.js': [15]}
    """    
    
    # Construct GitHub raw URL for the CSV file
    base_url = f"https://raw.githubusercontent.com/Samsung/CredData/{META_COMMIT}/meta/"
    csv_url = f"{base_url}{filename}.csv"
    
    try:
        # Fetch CSV content from GitHub
        response = requests.get(csv_url)
        response.raise_for_status()
        
        # Read CSV into pandas DataFrame
        csv_content = StringIO(response.text)
        df = pd.read_csv(csv_content)
        
        # Filter rows where GroundTruth is 'T'
        ground_truth_df = df[df['GroundTruth'] == 'T']
        
        # Group by FileID and collect LineStart values
        result_dict = {}
        for file_id in ground_truth_df['FileID'].unique():
            lines = ground_truth_df[ground_truth_df['FileID'] == file_id]['LineStart'].tolist()
            result_dict[file_id] = lines
        
        total_lines = sum(len(v) for v in result_dict.values())
        #print(f"[+] Found {total_lines} ground truth lines across {len(result_dict)} files in {filename}.csv")
        
        return result_dict
        
    except requests.RequestException as e:
        print(f"[-] Error fetching file from GitHub: {e}")
        return {}
    except KeyError as e:
        print(f"[-] Column not found in CSV: {e}")
        return {}
    except Exception as e:
        print(f"[-] Error processing file: {e}")
        return {}

def main(args):

    if args.show_benchmark_result is True and len(args.target) > 0:
        path = args.target
        jsonFile = args.file
        folderNames =[name for name in os.listdir(path) if os.path.isdir(os.path.join(path, name))]
        finalList = {}
        for folder in folderNames:
            tmpResult = get_groundtruth_lines(folder)
            finalList = finalList | tmpResult

        with open(jsonFile, "r", encoding="utf-8") as f:
            data = json.load(f)

        result = {}
        for item in data.get("findings", []):
            filename = os.path.splitext(os.path.basename(item["file"]))[0]
            line = item["line"]
            result.setdefault(filename, []).append(line)

        gt_total = sum(len(v) for v in finalList.values())
        result_total = sum(len(v) for v in result.values())

        print(gt_total)
        print(result_total)

    else:
        # Eğer data klasörü varsa indirmeyi atla
        if os.path.isdir(DATA_DIR):
            print("CredData/data already exists. Skipping download.")
            return
        else:        
            #if not os.path.isdir(REPO_DIR) or not os.listdir(REPO_DIR):
            if os.path.isdir(REPO_DIR):
                shutil.rmtree(REPO_DIR)
            # 1. benchmark klasörü oluştur
            if not os.path.isdir(BENCHMARK_DIR):
                os.makedirs(BENCHMARK_DIR, exist_ok=True)
            # 2. CredData reposunu indir (yoksa)
            #run(["git", "clone", REPO_URL], cwd=BENCHMARK_DIR)    
            run(f"git clone {REPO_URL}", cwd=BENCHMARK_DIR)
            run(f"git checkout -q {DATA_COMMIT}", cwd=REPO_DIR)

        # 3. upgrade/download_data.py -> CredData/download_data.py (replace)
        src_download_script = os.path.join(UPGRADE_DIR, "download_data.py")
        dst_download_script = os.path.join(REPO_DIR, "download_data.py")

        if not os.path.isfile(src_download_script):
            raise FileNotFoundError("upgrade/download_data.py not found")

        shutil.copyfile(src_download_script, dst_download_script)

        # 4. download_data.py çalıştır (CredData içinde)
        run(f"{sys.executable} download_data.py --jobs {args.jobs}", cwd=REPO_DIR)

        # 5. CredData altında sadece data klasörü kalsın
        for item in os.listdir(REPO_DIR):
            path = os.path.join(REPO_DIR, item)
            if path != DATA_DIR:
                if os.path.isdir(path):
                    shutil.rmtree(path)
                else:
                    os.remove(path)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Secret Scanner Benchmark'
    )

    parser.add_argument(
        'target',
        help='Path to scan',
        nargs='?',
        default=""
    )

    parser.add_argument(
        'file',
        help='Json File to Compare',
        nargs='?',
        default=""
    )
    
    parser.add_argument(
        '--jobs',
        type=int,
        default=8,
        help='Parallel downloads (default: 8)'
    )

    parser.add_argument(
        '--show-benchmark-result', 
        action='store_true',
        default=False,
        help='Show benchmark result for given path.'
    )
    
    args = parser.parse_args()
    main(args)
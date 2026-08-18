"""
Script to download benign APK samples from F-Droid repository for dataset building.
"""

import argparse
import json
import ssl
import urllib.request
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "data" / "input"

F_DROID_INDEX_URL = "https://f-droid.org/repo/index-v1.json"
F_DROID_REPO_BASE = "https://f-droid.org/repo/"

def download_fdroid_apks(count: int = 50, output_dir: Path = DEFAULT_OUTPUT_DIR, max_size_mb: int = 30):
    output_dir.mkdir(parents=True, exist_ok=True)
    print("Fetching repository index from F-Droid (index-v1.json)...")
    
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    
    req = urllib.request.Request(F_DROID_INDEX_URL, headers=headers)
    
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=60) as response:
            data = json.loads(response.read().decode('utf-8'))
    except Exception as e:
        print(f"Error fetching F-Droid index: {e}")
        sys.exit(1)
        
    packages_dict = data.get("packages", {})
    print(f"Index loaded. Found {len(packages_dict)} application packages.")
    
    successful_downloads = 0
    
    for pkg_name, apk_list in packages_dict.items():
        if successful_downloads >= count:
            break
            
        if not apk_list:
            continue
            
        # Get the latest apk entry
        latest_apk = apk_list[0]
        apk_name = latest_apk.get("apkName")
        if not apk_name:
            continue
            
        size_bytes = latest_apk.get("size", 0)
        if size_bytes > max_size_mb * 1024 * 1024:
            continue
            
        target_path = output_dir / f"benign_{pkg_name}.apk"
        if target_path.exists() and target_path.stat().st_size > 0:
            print(f"[{successful_downloads+1}/{count}] Already exists: {target_path.name}")
            successful_downloads += 1
            continue
            
        apk_url = f"{F_DROID_REPO_BASE}{apk_name}"
        print(f"[{successful_downloads+1}/{count}] Downloading {pkg_name} ({size_bytes / (1024*1024):.2f} MB)...")
        
        try:
            download_req = urllib.request.Request(apk_url, headers=headers)
            with urllib.request.urlopen(download_req, context=ctx, timeout=60) as res:
                content = res.read()
                if len(content) < 1000:
                    print("  Skipping (download incomplete or invalid file)")
                    continue
                with open(target_path, "wb") as out_f:
                    out_f.write(content)
            print(f"  Saved: {target_path.name}")
            successful_downloads += 1
        except Exception as err:
            print(f"  Failed: {err}")
            continue

    print(f"\n[OK] Completed! Downloaded {successful_downloads} benign APKs to {output_dir}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download benign APKs from F-Droid repository")
    parser.add_argument("-n", "--count", type=int, default=20, help="Number of benign APKs to download")
    parser.add_argument("-o", "--output", type=str, default=str(DEFAULT_OUTPUT_DIR), help="Output directory")
    parser.add_argument("--max-size", type=int, default=30, help="Max APK size in MB")
    args = parser.parse_args()
    
    download_fdroid_apks(count=args.count, output_dir=Path(args.output), max_size_mb=args.max_size)

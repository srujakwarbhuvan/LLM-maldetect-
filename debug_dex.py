
import sys
from androguard.core.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat

apk_path = "data/input/Benign0B4063F10577580010E3A642F162390D87080B0EC14AFDF7D3245CE0FD0E1A57.apk"

print(f"Analyzing {apk_path}...")

try:
    a = APK(apk_path)
    print("APK loaded successfully.")
    
    # Method 1: get_all_dex()
    print("\nTrying get_all_dex()...")
    dex_files = list(a.get_all_dex())
    print(f"Found {len(dex_files)} DEX files via get_all_dex()")
    
    for i, dex in enumerate(dex_files):
        print(f"  DEX #{i} type: {type(dex)}")
        try:
            d = DalvikVMFormat(dex)
            print(f"  DEX #{i} parsed successfully. Strings: {len(d.get_strings())}")
        except Exception as e:
            print(f"  DEX #{i} parsing FAILED: {e}")

    # Method 2: get_dex()
    if not dex_files:
        print("\nTrying get_dex()...")
        dex = a.get_dex()
        if dex:
            print(f"Found DEX via get_dex(). Type: {type(dex)}")
            try:
                d = DalvikVMFormat(dex)
                print(f"  DEX parsed successfully. Strings: {len(d.get_strings())}")
            except Exception as e:
                print(f"  DEX parsing FAILED: {e}")
        else:
            print("No DEX found via get_dex()")

except Exception as e:
    print(f"APK loading failed: {e}")

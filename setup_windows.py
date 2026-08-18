"""
Quick installation and setup script for Windows.
Run this to get started immediately.
"""

import subprocess
import sys
from pathlib import Path

def run_command(cmd, description):
    """Run a command and print status."""
    print(f"\n{'='*60}")
    print(f" {description}")
    print(f"{'='*60}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(result.stdout)
    if result.stderr and "warning" not in result.stderr.lower():
        print(f" Warnings/Errors:\n{result.stderr}")
    return result.returncode == 0

def main():
    print("""
    
      APK Feature Extraction System - Setup Script        
       Version 0.1.0                                     
    
    """)
    
    # Check Python version
    python_version = sys.version_info
    print(f" Python version: {python_version.major}.{python_version.minor}.{python_version.micro}")
    
    if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 10):
        print(" ERROR: Python 3.10 or higher is required!")
        return
    
    # Create virtual environment
    if not Path("venv").exists():
        success = run_command(
            "python -m venv venv",
            "Creating virtual environment..."
        )
        if not success:
            print(" Failed to create virtual environment")
            return
    else:
        print("\n Virtual environment already exists")
    
    # Activate message
    print(f"\n{'='*60}")
    print("IMPORTANT: Activate the virtual environment:")
    print("   > venv\\Scripts\\activate")
    print(f"{'='*60}")
    
    # Install dependencies
    activate_and_install = """
    After activation, run:
    
    pip install -r requirements.txt
    pip install -e .
    
    Or run this in the activated environment:
    python -c "import subprocess; subprocess.run(['pip', 'install', '-r', 'requirements.txt']); subprocess.run(['pip', 'install', '-e', '.'])"
    """
    
    print(activate_and_install)
    
    # Setup directories
    print(f"\n{'='*60}")
    print(" Setting up project directories...")
    print(f"{'='*60}")
    
    try:
        from scripts.setup_directories import create_directories
        create_directories()
    except:
        # Manual directory creation
        dirs = ["data/input", "data/output", "data/logs", "tests/fixtures", "docs"]
        for d in dirs:
            Path(d).mkdir(parents=True, exist_ok=True)
        print(" Directories created")
    
    # Final instructions
    print(f"""
    {'='*60}
    SETUP COMPLETE!
    {'='*60}
    
    Next steps:
    
    1. Activate virtual environment:
       > venv\\Scripts\\activate
    
    2. Install dependencies (if not done):
       > pip install -r requirements.txt
       > pip install -e .
    
    3. Place APK files in:
       data/input/
    
    4. Run extraction:
       > apk-extract batch data/input/ -o data/output/features.csv
    
    Or try the example:
       > python scripts/example_single_apk.py
    
    Documentation:
       - README.md           - Overview
       - QUICKSTART.md       - Getting started guide
       - PROJECT_SUMMARY.md  - Complete documentation
    
    Happy extracting!
    {'='*60}
    """)

if __name__ == "__main__":
    main()

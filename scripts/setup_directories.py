"""Create directory structure for data organization."""

from pathlib import Path

def create_directories():
    """Create necessary directories for the project."""
    
    directories = [
        "data/input",
        "data/output",
        "data/logs",
        "tests/fixtures",
        "docs",
    ]
    
    for dir_path in directories:
        path = Path(dir_path)
        path.mkdir(parents=True, exist_ok=True)
        print(f"✓ Created: {dir_path}")
    
    # Create .gitkeep files to preserve empty directories
    gitkeep_dirs = [
        "data/input",
        "data/output",
        "data/logs",
        "tests/fixtures",
    ]
    
    for dir_path in gitkeep_dirs:
        gitkeep = Path(dir_path) / ".gitkeep"
        gitkeep.touch()
    
    print("\n✓ Directory structure created successfully!")
    print("\nProjects structure:")
    print("  data/")
    print("    ├── input/    (place APK files here)")
    print("    ├── output/   (extracted features)")
    print("    └── logs/     (extraction logs)")
    print("  tests/")
    print("    └── fixtures/ (test APKs)")
    print("  docs/           (documentation)")

if __name__ == "__main__":
    create_directories()
